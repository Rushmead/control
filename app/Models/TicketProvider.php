<?php

namespace App\Models;

use App\Models\Traits\ToString;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

/**
 * App\Models\TicketProvider
 *
 * @property int $id
 * @property string $name
 * @property string $code
 * @property string $provider_class
 * @property mixed|null $apikey
 * @property int $enabled
 * @property \Illuminate\Support\Carbon|null $created_at
 * @property \Illuminate\Support\Carbon|null $updated_at
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider newModelQuery()
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider newQuery()
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider query()
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider whereApikey($value)
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider whereCode($value)
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider whereCreatedAt($value)
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider whereEnabled($value)
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider whereId($value)
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider whereName($value)
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider whereProviderClass($value)
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider whereUpdatedAt($value)
 * @property-read \Illuminate\Database\Eloquent\Collection<int, \App\Models\Ticket> $tickets
 * @property-read int|null $tickets_count
 * @property string|null $webhook_secret
 * @method static \Illuminate\Database\Eloquent\Builder|TicketProvider whereWebhookSecret($value)
 * @property-read \Illuminate\Database\Eloquent\Collection<int, \App\Models\EventMapping> $events
 * @property-read int|null $events_count
 * @property-read \Illuminate\Database\Eloquent\Collection<int, \App\Models\TicketTypeMapping> $types
 * @property-read int|null $types_count
 * @mixin \Eloquent
 * @mixin IdeHelperTicketProvider
 */
class TicketProvider extends Model
{
    use HasFactory, ToString;

    protected $hidden = [
        'apikey',
        'webhook_secret',
    ];

    protected $casts = [
        'apikey' => 'encrypted',
        'webhook_secret' => 'encrypted',
    ];

    public function tickets(): HasMany
    {
        return $this->hasMany(Ticket::class);
    }

    public function events(): HasMany
    {
        return $this->hasMany(EventMapping::class);
    }

    public function types(): HasMany
    {
        return $this->hasMany(TicketTypeMapping::class);
    }

    protected function toStringName(): string
    {
        return $this->code;
    }

    public function getProvider(?string $redirectUrl = null)
    {
        return new $this->provider_class($this);
    }

    public function syncTicket(string $id): ?Ticket
    {
        return $this->getProvider()->syncTicket($id);
    }

    public function syncTickets(EmailAddress $email): void
    {
        $this->getProvider()->syncTickets($email);
    }

    public function processWebhook(Request $request): bool
    {
        return $this->getProvider()->processWebhook($request);
    }

    public function getEvents(): array
    {
        return $this->getProvider()->getEvents();
    }

    public function getTicketTypes(Event $event): array
    {
        if (!$this->enabled) {
            return [];
        }

        $providerEvent = $this->events()->whereEventId($event->id)->first();
        if (!$providerEvent) {
            return [];
        }

        $types = $this->getProvider()->getTicketTypes($providerEvent->external_id);
        if (!$types) {
            return [];
        }

        $ids = array_keys($types);
        $existing = $this->types()
            ->whereIn('external_id', $ids)
            ->whereHas('type', function($query) use ($event) {
                $query->where('event_id', $event->id);
            })->get();

        $data = [];
        foreach ($types as $id => $name) {
            $data[] = (object)[
                'id' => $id,
                'name' => $name,
                'used' => $existing->where('external_id', $id)->count() > 0,
                'used_by' => $existing->where('external_id', $id),
            ];
        }
        return $data;
    }

    public function clearCache(): void
    {
        $this->cache_prefix = time();
        $this->save();
    }
}
