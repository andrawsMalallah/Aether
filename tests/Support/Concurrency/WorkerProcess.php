<?php

namespace Tests\Support\Concurrency;

use RuntimeException;

final class WorkerProcess
{
    /** @var resource */
    private $process;

    /** @var array<int, resource> */
    private array $pipes = [];

    /** @var resource */
    private $eventsFile;

    private string $buffer = '';

    /** @var list<array<string, mixed>> */
    private array $events = [];

    /** @param array<string, mixed> $input */
    public function __construct(array $input)
    {
        // Windows anonymous output pipes cannot reliably provide nonblocking reads.
        // Only sanitized worker events go to this run-owned file; credentials use stdin.
        $eventsPath = tempnam(sys_get_temp_dir(), 'aether-race-');
        if ($eventsPath === false) {
            throw new RuntimeException('Unable to prepare worker event stream.');
        }
        $this->eventsFile = fopen($eventsPath, 'r');
        $this->process = proc_open([PHP_BINARY, '-d', 'display_errors=0', '-d', 'log_errors=0', __DIR__.'/worker.php'],
            [0 => ['pipe', 'r'], 1 => ['file', $eventsPath, 'a'], 2 => ['file', PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null', 'w']], $this->pipes,
            Bootstrap::root(), null, ['bypass_shell' => true, 'blocking_pipes' => false]);
        if (! is_resource($this->process)) {
            throw new RuntimeException('Unable to start concurrency worker.');
        }
        $this->send($input);
    }

    /** @param array<string, mixed> $command */
    public function send(array $command): void
    {
        $message = json_encode($command, JSON_THROW_ON_ERROR)."\n";
        while ($message !== '') {
            $written = fwrite($this->pipes[0], $message);
            if ($written === false || $written === 0) {
                throw new RuntimeException('Worker input pipe failed.');
            }
            $message = substr($message, $written);
        }
        fflush($this->pipes[0]);
    }

    public function pump(): void
    {
        $this->buffer .= stream_get_contents($this->eventsFile);
        while (($newline = strpos($this->buffer, "\n")) !== false) {
            $line = substr($this->buffer, 0, $newline);
            $this->buffer = substr($this->buffer, $newline + 1);
            $event = json_decode($line, true);
            if (is_array($event) && ($event['type'] ?? null) === 'worker_failure') {
                throw new RuntimeException('Worker failed at '.$event['source_file'].':'.$event['source_line'].' ('.$event['exception_class'].').');
            }
            if (! is_array($event) || ! in_array($event['type'] ?? null, ['ready', 'attempt', 'paused', 'result'], true)) {
                throw new RuntimeException('Worker failed or emitted an invalid protocol message.');
            }
            $this->events[] = $event;
        }
    }

    /** @return array<string, mixed>|null */
    public function event(string $type): ?array
    {
        $this->pump();
        foreach ($this->events as $event) {
            if ($event['type'] === $type) {
                return $event;
            }
        }

        return null;
    }

    /** @return array<string, mixed> */
    public function await(string $type, int $seconds = 20): array
    {
        $deadline = microtime(true) + $seconds;
        do {
            if (($event = $this->event($type)) !== null) {
                return $event;
            }
            if ($this->event('result') !== null && $type !== 'result') {
                throw new RuntimeException('Worker finished before the required barrier.');
            }
            usleep(10000);
        } while (microtime(true) < $deadline);
        throw new RuntimeException('Worker barrier timed out.');
    }

    public function close(): void
    {
        if (is_resource($this->process)) {
            if (proc_get_status($this->process)['running']) {
                proc_terminate($this->process);
            }
            foreach ($this->pipes as $pipe) {
                fclose($pipe);
            }
            fclose($this->eventsFile);
            proc_close($this->process);
        }
    }
}
