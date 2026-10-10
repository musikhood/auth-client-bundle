<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Command;

use Musikhood\AuthClient\AiGuide;
use Musikhood\AuthClient\Doctor\AuthDoctor;
use Musikhood\AuthClient\Doctor\CheckResult;
use Musikhood\AuthClient\Doctor\CheckStatus;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;

/**
 * `bin/console auth-client:doctor` — checks env, connectivity, client
 * credentials, security.yaml coverage, CORS, cookies and trusted proxies.
 * Exit code 1 when any check fails (usable in CI / deploy smoke tests).
 */
#[AsCommand(name: 'auth-client:doctor', description: 'Sprawdza integrację panelu z auth serverem (env, połączenie, security, CORS, ciasteczka).')]
final class DoctorCommand extends Command
{
    public function __construct(
        private readonly AuthDoctor $doctor,
        #[Autowire('%kernel.project_dir%')]
        private readonly string $projectDir,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->addOption('access-token', null, InputOption::VALUE_REQUIRED, 'Wartość ciasteczka BEARER zalogowanego usera — dodatkowo sprawdza, czy AUTH_PANEL_ID należy do klienta.');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $token = $input->getOption('access-token');
        $results = $this->doctor->run(\is_string($token) ? $token : null);

        $output->writeln('<info>auth-client:doctor</info>');
        foreach ($results as $result) {
            $this->render($output, $result);
        }

        $failed = AuthDoctor::hasFailures($results);
        $output->writeln('');
        $output->writeln($failed
            ? '<error> Są błędy — popraw pozycje oznaczone ✘ i uruchom ponownie. </error>'
            : '<info>Wszystko gotowe ✔</info> (ostrzeżenia ! nie blokują działania).');
        $output->writeln(AiGuide::line($this->projectDir));

        return $failed ? Command::FAILURE : Command::SUCCESS;
    }

    private function render(OutputInterface $output, CheckResult $result): void
    {
        [$icon, $style] = match ($result->status) {
            CheckStatus::Ok => ['✔', 'info'],
            CheckStatus::Warning => ['!', 'comment'],
            CheckStatus::Failure => ['✘', 'error'],
            CheckStatus::Skipped => ['–', 'comment'],
        };

        $line = sprintf('  <%s>%s</%s> %s', $style, $icon, $style, $result->label);
        if (null !== $result->detail) {
            $line .= ' — ' . $result->detail;
        }
        $output->writeln($line);

        if (null !== $result->hint) {
            $output->writeln(sprintf('      → %s', $result->hint));
        }
    }
}
