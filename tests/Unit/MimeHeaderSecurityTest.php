<?php

use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Exception\RfcComplianceException;
use Symfony\Component\Mime\Header\Headers;
use Symfony\Component\Mime\Header\ParameterizedHeader;

it('rejects non-token MIME parameter names at every public entry point', function (string $parameterName, string $entryPoint): void {
    $header = new ParameterizedHeader('Content-Disposition', 'attachment', ['filename' => 'report.json']);
    $headers = new Headers;
    $headers->add($header);

    expect(fn () => match ($entryPoint) {
        'constructor' => new ParameterizedHeader('Content-Disposition', 'attachment', [$parameterName => 'value']),
        'single setter' => $header->setParameter($parameterName, 'value'),
        'bulk setter' => $header->setParameters([$parameterName => 'value']),
        'collection constructor' => $headers->addParameterizedHeader('Content-Type', 'text/plain', [$parameterName => 'value']),
        'collection setter' => $headers->setHeaderParameter('Content-Disposition', $parameterName, 'value'),
    })->toThrow(RfcComplianceException::class);

    // Rejection must preserve the valid state for callers that handle the exception.
    expect($header->getParameters())->toBe(['filename' => 'report.json']);
})->with([
    'injected header' => ["filename\r\nX-Injected: yes"],
    'carriage return' => ["file\rname"],
    'line feed' => ["file\nname"],
    'space' => ['file name'],
    'tab' => ["file\tname"],
    'delimiter' => ['file;name'],
    'equals' => ['file=name'],
    'non-ASCII' => ['filénامe'],
    'empty' => [''],
])->with(['constructor', 'single setter', 'bulk setter', 'collection constructor', 'collection setter']);

it('preserves ordinary MIME parameters and safely quotes filenames', function (): void {
    $contentType = new ParameterizedHeader('Content-Type', 'text/plain', ['charset' => 'utf-8']);
    $disposition = new ParameterizedHeader('Content-Disposition', 'attachment', ['filename' => 'monthly "report".json']);

    expect($contentType->getBodyAsString())->toBe('text/plain; charset=utf-8')
        ->and($disposition->getParameter('filename'))->toBe('monthly "report".json')
        ->and($disposition->getBodyAsString())->toBe('attachment; filename="monthly \\"report\\".json"');

    $disposition->setParameter('x-report_id', 'export-123');
    expect($disposition->getBodyAsString())->toContain('x-report_id=export-123');
});

it('serializes a normal multipart email with a JSON attachment', function (): void {
    $email = (new Email)
        ->from('sender@example.test')
        ->to('recipient@example.test')
        ->subject('Account export')
        ->text('Your account export is attached.')
        ->html('<p>Your account export is attached.</p>')
        ->attach('{"name":"Example"}', 'account export.json', 'application/json');

    expect($email->toString())
        ->toContain('Content-Type: multipart/mixed;', 'Content-Type: multipart/alternative;', 'Content-Type: application/json;', 'filename="account export.json"')
        ->not->toContain("\r\nX-Injected:");
});
