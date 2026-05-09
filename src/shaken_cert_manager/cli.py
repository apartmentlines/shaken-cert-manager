"""Command-line interface for SHAKEN certificate management."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

import argcomplete
from argcomplete.completers import FilesCompleter

from shaken_cert_manager.config import ManagerConfig
from shaken_cert_manager.errors import ManagerError
from shaken_cert_manager.manager import ShakenCertManager

SUCCESS_EXIT_CODE = 0
FAILURE_EXIT_CODE = 1
YAML_EXTENSIONS = (".yaml", ".yml")


class ShakenCertManagerCli:
    """CLI wrapper for :class:`ShakenCertManager`."""

    def run(self, argv: list[str] | None = None) -> int:
        """Run the CLI.

        :param argv: Optional argument vector.
        :type argv: list[str] | None
        :return: Exit code.
        :rtype: int
        """

        args = self.parse_args(argv)
        logging.basicConfig(
            level=logging.DEBUG if args.debug else logging.INFO,
            format="%(levelname)s %(message)s",
        )
        try:
            config = ManagerConfig.load(Path(args.config))
            manager = ShakenCertManager(config)
            if args.command == "status":
                return manager.status(nagios=args.nagios, json_output=args.json)
            if args.command == "renew":
                return manager.renew()
            if args.command == "force-renew":
                self.confirm_force_renew(args.skip_confirm)
                return manager.force_renew()
            if args.command == "issue-initial":
                return manager.issue_initial()
            if args.command == "cleanup":
                return manager.cleanup()
            if args.command == "clear-lock":
                self.confirm_clear_lock(args.skip_confirm)
                return manager.clear_lock()
            raise ManagerError(f"Unsupported command: {args.command}")
        except RuntimeError as exc:
            logging.error("%s", exc)
            return FAILURE_EXIT_CODE

    def parse_args(self, argv: list[str] | None) -> argparse.Namespace:
        """Parse CLI arguments.

        :param argv: Optional argument vector.
        :type argv: list[str] | None
        :return: Parsed arguments.
        :rtype: argparse.Namespace
        """

        parser = argparse.ArgumentParser(
            description="SHAKEN certificate issuance and renewal manager"
        )
        self.add_file_argument(
            parser,
            "--config",
            required=True,
            help="Manager YAML config path",
            extensions=YAML_EXTENSIONS,
        )
        parser.add_argument("--debug", action="store_true", help="Enable debug logging")
        subparsers = parser.add_subparsers(dest="command", required=True)
        status_parser = subparsers.add_parser(
            "status", help="Show active certificate status"
        )
        status_parser.add_argument(
            "--json", action="store_true", help="Print JSON status"
        )
        status_parser.add_argument(
            "--nagios", action="store_true", help="Print Nagios plugin status"
        )
        subparsers.add_parser("renew", help="Renew if policy requires it")
        force_parser = subparsers.add_parser("force-renew", help="Force a renewal")
        force_parser.add_argument(
            "--skip-confirm",
            action="store_true",
            help="Run force-renew without interactive confirmation",
        )
        subparsers.add_parser(
            "issue-initial", help="Issue only when no active certificate exists"
        )
        subparsers.add_parser("cleanup", help="Remove expired inactive material")
        clear_lock_parser = subparsers.add_parser(
            "clear-lock", help="Clear a stale manager lock"
        )
        clear_lock_parser.add_argument(
            "--skip-confirm",
            action="store_true",
            help="Clear a stale lock without interactive confirmation",
        )
        argcomplete.autocomplete(parser)
        return parser.parse_args(argv)

    def add_file_argument(
        self,
        parser: argparse.ArgumentParser,
        *flags: str,
        help: str,
        extensions: tuple[str, ...],
        **kwargs: Any,
    ) -> argparse.Action:
        """Add a file path argument with shell completion metadata.

        :param parser: Parser receiving the argument.
        :type parser: argparse.ArgumentParser
        :param flags: CLI flags for the argument.
        :type flags: str
        :param help: Help text for the argument.
        :type help: str
        :param extensions: File extensions to complete.
        :type extensions: tuple[str, ...]
        :param kwargs: Additional argparse keyword arguments.
        :type kwargs: Any
        :return: Added argparse action.
        :rtype: argparse.Action
        """

        action = parser.add_argument(*flags, help=help, **kwargs)
        setattr(action, "completer", FilesCompleter(allowednames=extensions))
        return action

    def confirm_force_renew(self, skip_confirm: bool) -> None:
        """Confirm an explicit force renewal.

        :param skip_confirm: Skip interactive confirmation.
        :type skip_confirm: bool
        :return: None.
        :rtype: None
        :raises ManagerError: If confirmation is refused or unavailable.
        """

        if skip_confirm:
            return
        if not sys.stdin.isatty():
            raise ManagerError("force-renew requires --skip-confirm when non-interactive")
        answer = input("Force certificate renewal now? Type 'yes' to continue: ")
        if answer != "yes":
            raise ManagerError("force-renew cancelled")

    def confirm_clear_lock(self, skip_confirm: bool) -> None:
        """Confirm lock removal.

        :param skip_confirm: Skip interactive confirmation.
        :type skip_confirm: bool
        :return: None.
        :rtype: None
        :raises ManagerError: If confirmation is refused or unavailable.
        """

        if skip_confirm:
            return
        if not sys.stdin.isatty():
            raise ManagerError("clear-lock requires --skip-confirm when non-interactive")
        answer = input("Clear stale shaken-cert-manager lock? Type 'yes' to continue: ")
        if answer != "yes":
            raise ManagerError("clear-lock cancelled")


def main() -> int:
    """Run the CLI entry point.

    :return: Exit code.
    :rtype: int
    """

    return ShakenCertManagerCli().run()


if __name__ == "__main__":
    sys.exit(main())
