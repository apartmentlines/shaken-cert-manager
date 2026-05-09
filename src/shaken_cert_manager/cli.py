"""Command-line interface for SHAKEN certificate management."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from shaken_cert_manager.config import ManagerConfig
from shaken_cert_manager.errors import ManagerError
from shaken_cert_manager.manager import ShakenCertManager

SUCCESS_EXIT_CODE = 0
FAILURE_EXIT_CODE = 1


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
                return manager.renew(wait_lock=args.wait_lock)
            if args.command == "force-renew":
                self.confirm_force_renew(args.skip_confirm)
                return manager.force_renew(wait_lock=args.wait_lock)
            if args.command == "issue-initial":
                return manager.issue_initial(wait_lock=args.wait_lock)
            if args.command == "cleanup":
                return manager.cleanup(wait_lock=args.wait_lock)
            if args.command == "account-status":
                return manager.account_status(wait_lock=args.wait_lock)
            if args.command == "validate":
                result = manager.validate_key_cert_pair(
                    Path(args.key), Path(args.certificate)
                )
                print(result.summary)
                return result.code
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
        parser.add_argument("--config", required=True, help="Manager YAML config path")
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
        renew_parser = subparsers.add_parser(
            "renew", help="Renew if policy requires it"
        )
        renew_parser.add_argument(
            "--wait-lock", action="store_true", help="Wait for an existing manager lock"
        )
        force_parser = subparsers.add_parser("force-renew", help="Force a renewal")
        force_parser.add_argument(
            "--wait-lock", action="store_true", help="Wait for an existing manager lock"
        )
        force_parser.add_argument(
            "--skip-confirm",
            action="store_true",
            help="Run force-renew without interactive confirmation",
        )
        initial_parser = subparsers.add_parser(
            "issue-initial", help="Issue only when no active certificate exists"
        )
        initial_parser.add_argument(
            "--wait-lock", action="store_true", help="Wait for an existing manager lock"
        )
        cleanup_parser = subparsers.add_parser(
            "cleanup", help="Remove expired inactive material"
        )
        cleanup_parser.add_argument(
            "--wait-lock", action="store_true", help="Wait for an existing manager lock"
        )
        account_parser = subparsers.add_parser(
            "account-status", help="Verify ACME account status"
        )
        account_parser.add_argument(
            "--wait-lock", action="store_true", help="Wait for an existing manager lock"
        )
        validate_parser = subparsers.add_parser(
            "validate", help="Validate a key/certificate pair"
        )
        validate_parser.add_argument("--key", required=True, help="Private key path")
        validate_parser.add_argument(
            "--certificate", required=True, help="Certificate path"
        )
        return parser.parse_args(argv)

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


def main() -> int:
    """Run the CLI entry point.

    :return: Exit code.
    :rtype: int
    """

    return ShakenCertManagerCli().run()


if __name__ == "__main__":
    sys.exit(main())
