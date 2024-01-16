<?php

namespace App\Services\SocialProviders;

use App\Exceptions\SocialProviderException;
use App\Models\EmailAddress;
use App\Models\LinkedAccount;
use App\Models\SocialProvider;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Laravel\Socialite\Facades\Socialite;
use SocialiteProviders\LaravelPassport\Provider;
use SocialiteProviders\Manager\Config;

class LaravelPassportProvider extends AbstractSocialProvider
{
    protected string $name = 'Laravel Passport';
    protected string $code = 'laravelpassport';
    protected string $socialiteProviderCode = 'laravelpassport';
    protected bool $supportsAuth = true;
    protected bool $canBeRenamed = true;

    public function __construct(?SocialProvider $provider = null, ?string $redirectUrl = null)
    {
        parent::__construct($provider, $redirectUrl);
        if($provider != null) {
            $this->name = $provider->name;
        }
    }

    protected function getSocialiteProvider()
    {
        $config = new Config(
            $this->provider->getSetting('client_id'),
            $this->provider->getSetting('client_secret'),
            $this->redirectUrl,
            ['host' => $this->provider->host]
        );
        return Socialite::buildProvider(Provider::class, $config->get())
            ->setConfig($config)->with(['prompt' => 'none']);
    }

    public function configMapping(): array
    {
        return array_merge(
            parent::configMapping(),
            [
                'host' => (object)[
                    'name' => 'Passport Host',
                    'validation' => 'required|string',
                ],
            ],
        );
    }

    public function user(?User $localUser = null)
    {
        if ($localUser === null) {
            $localUser = Auth::user();
        }
        $remoteUser = $this->getSocialiteProvider()->user();

        DB::transaction(function () use ($localUser, $remoteUser) {
            // Find the account
            $account = $this->provider->accounts()->whereExternalId($remoteUser->getId())->first();
            if ($account && ($localUser !== null && $localUser->id != $account->user_id)) {
                throw new SocialProviderException('Account is already associated with another user');
            }

            // Find the email
            $email = EmailAddress::whereEmail($remoteUser->getEmail())->first();
            if ($email && ($localUser !== null && $localUser->id !== $email->user_id)) {
                if ($email->verified_at !== null) {
                    throw new SocialProviderException('Email is already associated with another user');
                } else {
                    // Unverified email, let's delete it
                    $email->delete();
                    $email = null;
                }
            }

            if ($email) {
                $localUser = $email->user;
            }

            if ($localUser === null) {
                if ($account) {
                    $localUser = $account->user;
                } elseif (!$this->provider->auth_enabled) {
                    throw new SocialProviderException('Unable to login with this account');
                } else {
                    $localUser = new User;
                    $localUser->nickname = $remoteUser->getNickname();
                    $localUser->name = $remoteUser->getName();
                    $localUser->save();
                }
            }

            if ($account === null) {
                $account = new LinkedAccount;
                $account->provider()->associate($this->provider);
                $account->user()->associate($localUser);
                $account->external_id = $remoteUser->getId();
                $account->save();
            }

            $this->updateAccount($account, $remoteUser);

            $remoteEmail = $remoteUser->getEmail();
            if ($remoteEmail !== null) {
                $email = EmailAddress::whereEmail($remoteEmail)->first();
                if ($email === null) {
                    $email = new EmailAddress();
                    $email->email = $remoteEmail;
                    $email->verified_at = Carbon::now();
                    $email->user()->associate($localUser);
                    $email->save();
                }
                $account->email()->associate($email);
                if (!$localUser->primaryEmail) {
                    $localUser->primaryEmail()->associate($email);
                }
            }

            $account->save();
            $localUser->save();
        });

        if ($localUser === null) {
            $localUser = $this->provider->accounts()->whereExternalId($remoteUser->getId())->with('user')->first()->user;
        }
        return $localUser;
    }
    protected function updateAccount(LinkedAccount $account, $remoteUser): void
    {
        $account->avatar_url = $remoteUser->getAvatar();
        $account->refresh_token = $remoteUser->refreshToken;
        $account->access_token = $remoteUser->token;
        $account->name = $remoteUser->getNickname();
    }
}
