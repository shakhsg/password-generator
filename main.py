"""
main.py — Password Guardian CLI
A powerful, interactive terminal interface for generating and analysing passwords.

Usage:
    python main.py              → Interactive mode
    python main.py --generate   → Quick generate
    python main.py --check      → Check a password
    python main.py --batch 10   → Generate 10 passwords
    python main.py --passphrase → Generate a passphrase
"""

import argparse
import math
import sys
from getpass import getpass

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm, IntPrompt
    from rich.columns import Columns
    from rich import box
    from rich.text import Text
    from rich.rule import Rule
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from generator import PasswordGenerator, GeneratorConfig, PASSPHRASE_POOL
from checker   import StrengthChecker
from validator import PasswordPolicy

console = Console() if RICH_AVAILABLE else None


# ─── Display Helpers ───────────────────────────────────────────────────────────

def header():
    if not RICH_AVAILABLE:
        print("\n=== PASSWORD GUARDIAN ===\n")
        return
    console.print(Panel.fit(
        "[bold cyan]🔐  PASSWORD GUARDIAN[/bold cyan]\n"
        "[dim]Cryptographically secure generation · Entropy analysis · Policy validation[/dim]",
        border_style="cyan", padding=(1, 4),
    ))
    console.print()


def print_password_result(result, report=None, policy_result=None):
    if not RICH_AVAILABLE:
        print(f"\nPassword : {result.password}")
        print(f"Entropy  : {result.entropy_bits:.1f} bits")
        if report:
            print(f"Strength : {report.label} ({report.score}/100)")
            print(f"Crack    : {report.crack_time_label}")
        return

    # Password panel
    pw_text = Text(result.password, style="bold bright_white on grey11")
    console.print(Panel(pw_text, title="[cyan]Generated Password[/cyan]",
                         border_style="cyan", padding=(0, 2)))

    # Stats table
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Key",   style="dim")
    table.add_column("Value", style="bold")

    table.add_row("Length",       str(result.length))
    table.add_row("Charset Size", str(result.charset_size))
    table.add_row("Entropy",      f"{result.entropy_bits:.1f} bits")

    if report:
        bar_color = report.color
        table.add_row("Strength",   f"[{bar_color}]{report.icon} {report.label}[/] ({report.score}/100)")
        table.add_row("Meter",      f"[{bar_color}]{report.bar}[/]")
        table.add_row("Crack Time", f"[bold]{report.crack_time_label}[/]")

    console.print(table)

    if report and report.penalties:
        console.print("[yellow]⚠  Warnings:[/yellow]")
        for p in report.penalties:
            console.print(f"   [yellow]• {p}[/yellow]")

    if policy_result:
        status = "[green]✓ PASS[/green]" if policy_result.passed else "[red]✗ FAIL[/red]"
        console.print(f"\nPolicy Check: {status}")
        if not policy_result.passed:
            for v in policy_result.violations:
                console.print(f"  [red]{v}[/red]")


# ─── Interactive Mode ──────────────────────────────────────────────────────────

def interactive_generate():
    gen     = PasswordGenerator()
    checker = StrengthChecker()
    policy  = PasswordPolicy.from_preset("strong")

    if RICH_AVAILABLE:
        console.print(Rule("[cyan]Generate Password[/cyan]"))
        length = IntPrompt.ask("  Length", default=16)
        use_sym = Confirm.ask("  Include symbols?", default=True)
        safe_sym = False
        if use_sym:
            safe_sym = Confirm.ask("  Safe symbols only (!@#$%^&*-_=+)?", default=False)
        excl_amb = Confirm.ask("  Exclude ambiguous chars (O, 0, I, l)?", default=False)
        batch = IntPrompt.ask("  How many passwords?", default=1)
    else:
        length   = int(input("Length [16]: ") or 16)
        use_sym  = input("Include symbols? [Y/n]: ").lower() != "n"
        safe_sym = use_sym and input("Safe symbols only? [y/N]: ").lower() == "y"
        excl_amb = input("Exclude ambiguous chars? [y/N]: ").lower() == "y"
        batch    = int(input("How many passwords? [1]: ") or 1)

    cfg = GeneratorConfig(
        length=length, use_symbols=use_sym,
        use_safe_symbols=safe_sym, exclude_ambiguous=excl_amb,
    )

    results = gen.generate_batch(batch, cfg)
    if RICH_AVAILABLE:
        console.print()

    for i, result in enumerate(results, 1):
        if batch > 1 and RICH_AVAILABLE:
            console.print(f"[dim]── Password {i} ──[/dim]")
        report        = checker.check(result.password)
        policy_result = policy.validate(result.password)
        print_password_result(result, report, policy_result)
        if RICH_AVAILABLE:
            console.print()


def interactive_check():
    checker = StrengthChecker()

    if RICH_AVAILABLE:
        console.print(Rule("[cyan]Check Password Strength[/cyan]"))
        password = Prompt.ask("  Enter password (input hidden)", password=True)
    else:
        password = getpass("Enter password: ")

    report = checker.check(password)

    if not RICH_AVAILABLE:
        print(f"\nStrength : {report.label} ({report.score}/100)")
        print(f"Entropy  : {report.entropy_bits} bits")
        print(f"Crack    : {report.crack_time_label}")
        if report.suggestions:
            print("\nSuggestions:")
            for s in report.suggestions:
                print(f"  • {s}")
        return

    console.print()
    bar_c = report.color
    console.print(Panel(
        f"[{bar_c}]{report.icon}  {report.label}[/]  ({report.score}/100)\n"
        f"[{bar_c}]{report.bar}[/]\n\n"
        f"Entropy   : [bold]{report.entropy_bits} bits[/bold]\n"
        f"Crack est : [bold]{report.crack_time_label}[/bold]",
        title="[cyan]Strength Report[/cyan]", border_style="cyan",
    ))

    # Checklist
    checks = [
        ("Uppercase",  report.has_upper),
        ("Lowercase",  report.has_lower),
        ("Digits",     report.has_digit),
        ("Symbols",    report.has_symbol),
        ("Length ≥12", report.length >= 12),
        ("Length ≥20", report.length >= 20),
    ]
    t = Table(show_header=False, box=box.SIMPLE)
    t.add_column("Check"); t.add_column("Status")
    for name, ok in checks:
        t.add_row(name, "[green]✓[/green]" if ok else "[red]✗[/red]")
    console.print(t)

    if report.penalties:
        for p in report.penalties:
            console.print(f"  [yellow]⚠  {p}[/yellow]")
    if report.suggestions:
        console.print("\n[bold]Suggestions:[/bold]")
        for s in report.suggestions:
            console.print(f"  [cyan]→[/cyan] {s}")


def interactive_passphrase():
    gen = PasswordGenerator()
    if RICH_AVAILABLE:
        console.print(Rule("[cyan]Generate Passphrase[/cyan]"))
        words = IntPrompt.ask("  Number of words", default=4)
        sep   = Prompt.ask("  Separator", default="-")
    else:
        words = int(input("Number of words [4]: ") or 4)
        sep   = input("Separator [-]: ") or "-"

    phrase = gen.generate_passphrase(words=words, separator=sep)
    if RICH_AVAILABLE:
        console.print(Panel(f"[bold bright_white]{phrase}[/bold bright_white]",
                             title="[cyan]Passphrase[/cyan]", border_style="cyan"))
        entropy = words * math.log2(len(PASSPHRASE_POOL))
        console.print(f"  Estimated entropy: [bold]~{entropy:.1f} bits[/bold] ({words} words × log₂({len(PASSPHRASE_POOL)}) ≈ {math.log2(len(PASSPHRASE_POOL)):.1f} bits/word)")
    else:
        print(f"\nPassphrase: {phrase}")


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🔐 Password Guardian — Secure Generation & Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    Interactive menu
  python main.py --generate -l 24  Generate a 24-char password
  python main.py --check            Check password strength
  python main.py --batch 10 -l 20  Generate 10 passwords of length 20
  python main.py --passphrase -w 5  Generate a 5-word passphrase
        """
    )
    parser.add_argument("--generate",   action="store_true", help="Quick generate mode")
    parser.add_argument("--check",      action="store_true", help="Check password strength")
    parser.add_argument("--passphrase", action="store_true", help="Generate passphrase")
    parser.add_argument("--batch",      type=int, metavar="N", help="Generate N passwords")
    parser.add_argument("-l", "--length", type=int, default=16, help="Password length")
    parser.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
    parser.add_argument("--safe-symbols", action="store_true", help="Use safe symbols only")
    parser.add_argument("--no-ambiguous", action="store_true", help="Exclude ambiguous chars")
    parser.add_argument("-w", "--words", type=int, default=4, help="Passphrase word count")
    args = parser.parse_args()

    header()

    if args.check:
        interactive_check()
        return

    if args.passphrase:
        gen    = PasswordGenerator()
        phrase = gen.generate_passphrase(words=args.words)
        if RICH_AVAILABLE:
            console.print(Panel(f"[bold bright_white]{phrase}[/bold bright_white]",
                                 title="Passphrase", border_style="cyan"))
        else:
            print(phrase)
        return

    if args.generate or args.batch:
        gen     = PasswordGenerator()
        checker = StrengthChecker()
        policy  = PasswordPolicy.from_preset("strong")
        cfg = GeneratorConfig(
            length=args.length,
            use_symbols=not args.no_symbols,
            use_safe_symbols=args.safe_symbols,
            exclude_ambiguous=args.no_ambiguous,
        )
        count = args.batch or 1
        for result in gen.generate_batch(count, cfg):
            report        = checker.check(result.password)
            policy_result = policy.validate(result.password)
            print_password_result(result, report, policy_result)
            if RICH_AVAILABLE: console.print()
        return

    # Interactive menu
    while True:
        if RICH_AVAILABLE:
            console.print("\n[bold cyan]What would you like to do?[/bold cyan]")
            console.print("  [cyan]1[/cyan]  Generate password(s)")
            console.print("  [cyan]2[/cyan]  Check password strength")
            console.print("  [cyan]3[/cyan]  Generate passphrase")
            console.print("  [cyan]0[/cyan]  Exit")
            choice = Prompt.ask("\n  Choice", choices=["0","1","2","3"], default="1")
        else:
            print("\n1. Generate password\n2. Check strength\n3. Passphrase\n0. Exit")
            choice = input("Choice: ").strip()

        if choice == "1": interactive_generate()
        elif choice == "2": interactive_check()
        elif choice == "3": interactive_passphrase()
        elif choice == "0":
            if RICH_AVAILABLE: console.print("[dim]Goodbye! Stay secure 🔐[/dim]")
            sys.exit(0)


if __name__ == "__main__":
    main()