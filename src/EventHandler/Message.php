<?php declare(strict_types=1);

namespace danog\MadelineProto\EventHandler;

use danog\MadelineProto\EventHandler\Keyboard\InlineKeyboard;
use danog\MadelineProto\EventHandler\Keyboard\ReplyKeyboard;
use danog\MadelineProto\EventHandler\Media\Audio;
use danog\MadelineProto\EventHandler\Media\Document;
use danog\MadelineProto\EventHandler\Media\DocumentPhoto;
use danog\MadelineProto\EventHandler\Media\Gif;
use danog\MadelineProto\EventHandler\Media\MaskSticker;
use danog\MadelineProto\EventHandler\Media\Photo;
use danog\MadelineProto\EventHandler\Media\RoundVideo;
use danog\MadelineProto\EventHandler\Media\Sticker;
use danog\MadelineProto\EventHandler\Media\Video;
use danog\MadelineProto\EventHandler\Media\Voice;
use danog\MadelineProto\MTProto;
use danog\MadelineProto\ParseMode;
use danog\MadelineProto\StrTools;
use Webmozart\Assert\Assert;

/**
 * Represents an incoming or outgoing message.
 */
abstract class Message extends AbstractMessage
{
    /** Content of the message */
    public readonly string $message;

    /** @var list<int|string> list of our message reactions */
    protected array $reactions = [];

    /** Info about a forwarded message */
    public readonly ?ForwardedInfo $fwdInfo;

    /** Bot command (if present) */
    public readonly ?string $command;
    /** Bot command type (if present) */
    public readonly ?CommandType $commandType;
    /** @var list<string> Bot command arguments (if present) */
    public readonly ?array $commandArgs;

    /** Whether this message is protected */
    public readonly bool $protected;

    /**
     * @readonly
     *
     * @var list<string> Regex matches, if a filter regex is present
     */
    public ?array $matches = null;

    /**
     * Attached media.
     */
    public readonly Audio|Document|DocumentPhoto|Gif|MaskSticker|Photo|RoundVideo|Sticker|Video|Voice|null $media;

    /** Whether this message is a sent scheduled message */
    public readonly bool $fromScheduled;

    /** If the message was generated by an inline query, ID of the bot that generated it */
    public readonly ?int $viaBotId;

    /** Last edit date of the message */
    public readonly ?int $editDate;

    /** Inline or reply keyboard. */
    public readonly InlineKeyboard|ReplyKeyboard|null $keyboard;

    /** Whether this message was [imported from a foreign chat service](https://core.telegram.org/api/import) */
    public readonly bool $imported;

    /** For Public Service Announcement messages, the PSA type */
    public readonly ?string $psaType;

    /** @readonly For sent messages, contains the next message in the chain if the original message had to be split. */
    public ?self $nextSent = null;
    // Todo media (photosizes, thumbs), albums, reactions, games eventually

    /** @internal */
    public function __construct(
        MTProto $API,
        array $rawMessage,
        array $info,
    ) {
        parent::__construct($API, $rawMessage, $info);

        $this->entities = $rawMessage['entities'] ?? null;
        $this->message = $rawMessage['message'];
        $this->fromScheduled = $rawMessage['from_scheduled'];
        $this->viaBotId = $rawMessage['via_bot_id'] ?? null;
        $this->editDate = $rawMessage['edit_date'] ?? null;

        $this->keyboard = isset($rawMessage['reply_markup'])
            ? Keyboard::fromRawReplyMarkup($rawMessage['reply_markup'])
            : null;

        if (isset($rawMessage['fwd_from'])) {
            $fwdFrom = $rawMessage['fwd_from'];
            $this->fwdInfo = new ForwardedInfo(
                $fwdFrom['date'],
                isset($fwdFrom['from_id'])
                    ? $this->getClient()->getIdInternal($fwdFrom['from_id'])
                    : null,
                $fwdFrom['from_name'] ?? null,
                $fwdFrom['channel_post'] ?? null,
                $fwdFrom['post_author'] ?? null,
                isset($fwdFrom['saved_from_peer'])
                    ? $this->getClient()->getIdInternal($fwdFrom['saved_from_peer'])
                    : null,
                $fwdFrom['saved_from_msg_id'] ?? null
            );
            $this->psaType = $fwdFrom['psa_type'] ?? null;
            $this->imported = $fwdFrom['imported'];
        } else {
            $this->fwdInfo = null;
            $this->psaType = null;
            $this->imported = false;
        }

        $this->protected = $rawMessage['noforwards'];

        $this->media = isset($rawMessage['media'])
            ? $API->wrapMedia($rawMessage['media'], $this->protected)
            : null;

        if (\in_array($this->message[0] ?? '', ['/', '.', '!'], true)) {
            $space = \strpos($this->message, ' ', 1) ?: \strlen($this->message);
            $this->command = \substr($this->message, 1, $space-1);
            $args = \explode(
                ' ',
                \substr($this->message, $space+1)
            );
            $this->commandArgs = $args === [''] ? [] : $args;
            $this->commandType = match ($this->message[0]) {
                '.' => CommandType::DOT,
                '/' => CommandType::SLASH,
                '!' => CommandType::BANG,
            };
        } else {
            $this->command = null;
            $this->commandArgs = null;
            $this->commandType = null;
        }

        foreach ($rawMessage['reactions']['results'] ?? [] as $r) {
            if (isset($r['chosen_order'])) {
                // Todo: live synchronization using a message database...
                $this->reactions []= $r['reaction']['emoticon'] ?? $r['reaction']['document_id'];
            }
        }
    }

    /**
     * Pin a message.
     *
     * @param bool $pmOneside Whether the message should only be pinned on the local side of a one-to-one chat
     * @param bool $silent Pin the message silently, without triggering a notification
     */
    public function pin(bool $pmOneside = false, bool $silent = false): ?AbstractMessage
    {
        $result = $this->getClient()->methodCallAsyncRead(
            'messages.updatePinnedMessage',
            [
                'peer' => $this->chatId,
                'id' => $this->id,
                'pm_oneside' => $pmOneside,
                'silent' => $silent,
                'unpin' => false
            ]
        );
        return $this->getClient()->wrapMessage($this->getClient()->extractMessage($result));
    }

    /**
     * Unpin a message.
     *
     * @param bool $pmOneside Whether the message should only be pinned on the local side of a one-to-one chat
     * @param bool $silent Pin the message silently, without triggering a notification
     */
    public function unpin(bool $pmOneside = false, bool $silent = false): ?Update
    {
        $result = $this->getClient()->methodCallAsyncRead(
            'messages.updatePinnedMessage',
            [
                'peer' => $this->chatId,
                'id' => $this->id,
                'pm_oneside' => $pmOneside,
                'silent' => $silent,
                'unpin' => true
            ]
        );
        return $this->getClient()->wrapUpdate($result);
    }

    /**
     * Get our reactions on the message.
     *
     * @return list<string|int>
     */
    public function getOurReactions(): array
    {
        return $this->reactions;
    }

    /**
     * Add reaction to message.
     *
     * @param string|int $reaction reaction
     * @param bool $big Whether a bigger and longer reaction should be shown
     * @param bool $addToRecent Add this reaction to the recent reactions list.
     *
     * @return list<string|int>
     */
    public function addReaction(int|string $reaction, bool $big = false, bool $addToRecent = true): array
    {
        if (\in_array($reaction, $this->reactions, true)) {
            return $this->reactions;
        }
        $this->getClient()->methodCallAsyncRead(
            'messages.sendReaction',
            [
                'peer' => $this->chatId,
                'msg_id' => $this->id,
                'reaction' => \is_int($reaction)
                    ? [['_' => 'reactionCustomEmoji', 'document_id' => $reaction]]
                    : [['_' => 'reactionEmoji', 'emoticon' => $reaction]],
                'big' => $big,
                'add_to_recent' => $addToRecent
            ]
        );
        $this->reactions[] = $reaction;
        return $this->reactions;
    }

    /**
     * Delete reaction from message.
     *
     * @param string|int $reaction string or int Reaction
     *
     * @return list<string|int>
     */
    public function delReaction(int|string $reaction): array
    {
        $key = \array_search($reaction, $this->reactions, true);
        if ($key === false) {
            return $this->reactions;
        }
        unset($this->reactions[$key]);
        $this->reactions = \array_values($this->reactions);
        $r = \array_map(fn (string|int $r): array => \is_int($r) ? ['_' => 'reactionCustomEmoji', 'document_id' => $r] : ['_' => 'reactionEmoji', 'emoticon' => $r], $this->reactions);
        $r[]= ['_' => 'reactionEmpty'];
        $this->getClient()->methodCallAsyncRead(
            'messages.sendReaction',
            [
                'peer' => $this->chatId,
                'msg_id' => $this->id,
                'reaction' =>  $r,
            ]
        );
        return $this->reactions;
    }

    /**
     * Translate text message(for media translate it caption).
     *
     * @param string $toLang Two-letter ISO 639-1 language code of the language to which the message is translated
     *
     */
    public function translate(
        string $toLang = 'en'
    ): string {
        Assert::notEmpty($this->message);
        $result = $this->getClient()->methodCallAsyncRead(
            'messages.translateText',
            [
                'peer' => $this->chatId,
                'id' => [$this->id],
                'text' => $this->message,
                'to_lang' => $toLang
            ]
        );
        return $result[0]['text'];
    }

    /**
     * Edit message text.
     *
     * @param string $message New message
     * @param array|null $replyMarkup Reply markup for inline keyboards
     * @param array|null $entities Message entities for styled text
     * @param ParseMode $parseMode Whether to parse HTML or Markdown markup in the message
     * @param int|null $scheduleDate Scheduled message date for scheduled messages
     * @param bool $noWebpage Disable webpage preview
     *
     */
    public function edit(
        string    $message,
        ?array    $replyMarkup = null,
        ?array    $entities = null,
        ParseMode $parseMode = ParseMode::TEXT,
        ?int      $scheduleDate = null,
        bool      $noWebpage = false
    ): Message {
        Assert::notEmpty($this->message);
        $result = $this->getClient()->methodCallAsyncRead(
            'messages.editMessage',
            [
                'peer' => $this->chatId,
                'id' => $this->id,
                'message' => $message,
                'reply_markup' => $replyMarkup,
                'entities' => $entities,
                'parse_mode' => $parseMode,
                'schedule_date' => $scheduleDate,
                'no_webpage' => $noWebpage
            ]
        );
        if (isset($result['_'])) {
            return $this->getClient()->wrapMessage($this->getClient()->extractMessage($result));
        }

        $last = null;
        foreach ($result as $updates) {
            $new = $this->getClient()->wrapMessage($this->getClient()->extractMessage($updates));
            if ($last) {
                $last->nextSent = $new;
            } else {
                $first = $new;
            }
            $last = $new;
        }
        return $first;
    }

    protected readonly string $html;
    protected readonly string $htmlTelegram;
    protected readonly ?array $entities;

    /**
     * Get an HTML version of the message.
     *
     * @param bool $allowTelegramTags Whether to allow telegram-specific tags like tg-spoiler, tg-emoji, mention links and so on...
     */
    public function getHTML(bool $allowTelegramTags = false): string
    {
        if (!$this->entities) {
            return \htmlentities($this->message);
        }
        if ($allowTelegramTags) {
            return $this->htmlTelegram ??= StrTools::entitiesToHtml($this->message, $this->entities, $allowTelegramTags);
        }
        return $this->html ??= StrTools::entitiesToHtml($this->message, $this->entities, $allowTelegramTags);
    }
}
