<?php

declare(strict_types=1);

namespace Musikhood\AuthClient\Command;

use Musikhood\AuthClient\Install\ChangeKind;
use Musikhood\AuthClient\Install\Installer;
use Musikhood\AuthClient\Install\LineDiff;
use Musikhood\AuthClient\Install\PlannedChange;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ConfirmationQuestion;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpKernel\Kernel;

/**
 * `bin/console auth-client:install` — writes the integration config a panel
 * needs (security.yaml, CORS, trusted proxies) and runs the doctor.
 *
 * Never destroys existing configuration: a custom security.yaml or a CORS
 * file it cannot edit safely gets a snippet to paste instead.
 */
#[AsCommand(name: 'auth-client:install', description: 'Konfiguruje security.yaml, CORS i trusted proxies dla auth-client-bundle, potem uruchamia doctor.')]
final class InstallCommand extends Command
{
    private const NELMIO_BUNDLE = 'Nelmio\CorsBundle\NelmioCorsBundle';

    /**
     * @param array<string, mixed> $kernelBundles
     */
    public function __construct(
        #[Autowire('%kernel.project_dir%')]
        private readonly string $projectDir,
        #[Autowire('%kernel.bundles%')]
        private readonly array $kernelBundles,
        private readonly Installer $installer = new Installer(),
        private readonly int $symfonyVersionId = Kernel::VERSION_ID,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->addOption('dry-run', null, InputOption::VALUE_NONE, 'Pokaż zmiany bez zapisu.')
            ->addOption('yes', 'y', InputOption::VALUE_NONE, 'Zapisz bez pytania (CI / skrypty).')
            ->addOption('no-doctor', null, InputOption::VALUE_NONE, 'Nie uruchamiaj auth-client:doctor na końcu.');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $dryRun = (bool) $input->getOption('dry-run');
        $nelmio = \in_array(self::NELMIO_BUNDLE, $this->kernelBundles, true);
        $changes = $this->installer->plan($this->projectDir, $nelmio, $this->symfonyVersionId, self::definedEnv());

        $output->writeln(sprintf('<info>auth-client:install</info>%s', $dryRun ? ' <comment>(dry-run — nic nie zapisuję)</comment>' : ''));
        foreach ($changes as $change) {
            $this->render($output, $change);
        }

        $writes = array_values(array_filter($changes, static fn (PlannedChange $c): bool => $c->writes()));
        $manual = array_values(array_filter($changes, static fn (PlannedChange $c): bool => ChangeKind::Manual === $c->kind));

        if ([] === $writes) {
            $output->writeln('');
            $output->writeln('Brak zmian do zapisania.');
        } elseif ($dryRun) {
            $output->writeln('');
            $output->writeln(sprintf('Do zapisania: %d plik(ów). Uruchom bez --dry-run, aby zapisać.', \count($writes)));
        } else {
            $confirmed = (bool) $input->getOption('yes');
            if (!$confirmed && $input->isInteractive()) {
                $helper = $this->getHelper('question');
                \assert($helper instanceof \Symfony\Component\Console\Helper\QuestionHelper);
                $confirmed = (bool) $helper->ask($input, $output, new ConfirmationQuestion(sprintf("\nZapisać zmiany w %d plik(ach)? [Y/n] ", \count($writes)), true));
            }
            if (!$confirmed) {
                $output->writeln('<comment>Nic nie zapisano (tryb nieinteraktywny bez --yes albo odmowa).</comment>');

                return Command::FAILURE;
            }
            $this->installer->apply($this->projectDir, $writes);
            $output->writeln('<info>Zapisano.</info> Wyczyść cache, jeśli aplikacja działa w APP_ENV=prod (bin/console cache:clear).');
        }

        if ([] !== $manual) {
            $output->writeln(sprintf('<comment>Do zrobienia ręcznie: %d pozycja(e) oznaczone [ręcznie] powyżej.</comment>', \count($manual)));
        }

        if ($input->getOption('no-doctor')) {
            return Command::SUCCESS;
        }

        $output->writeln('');

        return $this->runDoctor($output, !$dryRun && [] !== $writes);
    }

    /**
     * Env names visible to this process — Symfony's Dotenv has already loaded
     * .env, .env.local, .env.<env>(.local) into $_SERVER / $_ENV, and real env
     * (k8s secrets) is in getenv().
     *
     * @return list<string>
     */
    private static function definedEnv(): array
    {
        $names = array_merge(array_keys($_SERVER), array_keys($_ENV), array_keys(getenv()));

        return array_values(array_unique(array_filter($names, 'is_string')));
    }

    private function render(OutputInterface $output, PlannedChange $change): void
    {
        $tag = match ($change->kind) {
            ChangeKind::Create => '<info>[utworzę]</info>',
            ChangeKind::Modify => '<info>[zmienię]</info>',
            ChangeKind::Manual => '<comment>[ręcznie]</comment>',
            ChangeKind::Unchanged => '[ok]',
        };
        $output->writeln('');
        $output->writeln(sprintf('%s %s — %s', $tag, $change->path, $change->summary));

        $body = match ($change->kind) {
            ChangeKind::Create => array_map(static fn (string $l): string => '+ ' . $l, explode("\n", rtrim((string) $change->newContent, "\n"))),
            ChangeKind::Modify => LineDiff::render((string) $change->oldContent, (string) $change->newContent),
            ChangeKind::Manual => explode("\n", rtrim((string) $change->snippet, "\n")),
            ChangeKind::Unchanged => [],
        };
        foreach ($body as $line) {
            $output->writeln('    ' . $line, OutputInterface::OUTPUT_RAW);
        }
    }

    private function runDoctor(OutputInterface $output, bool $configChanged): int
    {
        $console = $this->projectDir . '/bin/console';
        if ($configChanged && is_file($console)) {
            // Fresh process: this kernel still holds the configuration from before the write.
            $process = proc_open([\PHP_BINARY, $console, 'auth-client:doctor'], [1 => \STDOUT, 2 => \STDERR], $pipes, $this->projectDir);
            if (\is_resource($process)) {
                return 0 === proc_close($process) ? Command::SUCCESS : Command::FAILURE;
            }
        }

        $application = $this->getApplication();
        if (null === $application) {
            $output->writeln('Uruchom: bin/console auth-client:doctor');

            return Command::SUCCESS;
        }

        return $application->find('auth-client:doctor')->run(new ArrayInput([]), $output);
    }
}
