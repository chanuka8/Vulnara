import asyncio
from datetime import datetime
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, OptionList, RichLog, Button, Label
from textual.widgets.option_list import Option

from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.columns import Columns
from rich.align import Align
from rich.console import Group
from rich.rule import Rule


class VulnaraTUI(App):
    # command: Engineered UI layout with a solid vertical separator to distinctively isolate the sidebar from the main dashboard
    CSS = """
    Screen { background: #050505; }
    
    #sidebar { 
        width: 38; 
        height: 100%;
        border-right: solid #ff8c00; 
        background: #0a0a0a; 
    }
    
    #main_area { 
        width: 1fr; 
        height: 100%; 
        background: #050505; 
    }
    
    #top_bar {
        height: 5;
        width: 1fr;
        padding: 0 2;
        border-bottom: solid #ff8c00;
        background: #0a0a0a;
        align-vertical: middle;
    }
    
    #view_title {
        width: 1fr;
        content-align: left middle;
        text-style: bold;
        color: #ff8c00;
        height: 3;
    }
    
    #save_btn {
        display: none;
        min-width: 25;
        border: heavy $success;
        background: #050505;
        color: $success;
        text-style: bold;
    }
    
    #save_btn:hover {
        background: $success;
        color: #050505;
        text-style: bold;
    }
    """

    BINDINGS = [("q", "quit", "Quit Vulnara")]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.active_module = "General"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            yield OptionList(
                Option(" 📊 Dashboard", id="opt_dash"),
                Option(" ⚙️ Setup Project", id="opt_proj"),
                Option(" 🔍 Discovery Engine", id="opt_disc"),
                Option(" 🌐 Network Scan (Nmap)", id="opt_nmap"),
                Option(" 🧠 AI Threat Analysis", id="opt_ai"),
                Option(" 🚀 Full Assessment", id="opt_full"),
                id="sidebar"
            )
            with Vertical(id="main_area"):
                with Horizontal(id="top_bar"):
                    yield Label("VULNARA COMMAND CENTER", id="view_title")
                    yield Button("▼ EXPORT REPORT", id="save_btn")
                yield RichLog(id="log_view", highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Vulnara Security Tool"
        self.sub_title = "Advanced Threat Assessment & Reconnaissance"

        log_view = self.query_one("#log_view", RichLog)
        banner = r"""
           _    __      __                               
          | |  / /_  __/ /___  ____ ___________ _        
          | | / / / / / / __ \/ __ `/ ___/ __ `/         
          | |/ / /_/ / / / / / /_/ / /  / /_/ /          
          |___/\__,_/_/_/ /_/\__,_/_/   \__,_/           
        """
        log_view.write(Panel(Text(banner, style="bold cyan",
                       justify="center"), border_style="cyan"))
        log_view.write(
            "\n[bold green]Welcome to Vulnara Interactive TUI.[/bold green]")
        log_view.write(
            "[dim]Please select a service module from the left sidebar to begin.[/dim]")

    def _build_dashboard_ui(self) -> Group:
        title = Align.center(
            Text("⚡ VULNARA COMMAND CENTER ⚡", style="bold magenta"))

        p1 = Panel(Align.center(Text("12\nProjects", style="bold cyan")),
                   border_style="cyan", padding=(1, 2))
        p2 = Panel(Align.center(Text("47\nScans Done", style="bold green")),
                   border_style="green", padding=(1, 2))
        p3 = Panel(Align.center(Text("184\nVulns Found", style="bold red")),
                   border_style="red", padding=(1, 2))

        stats = Columns([p1, p2, p3], expand=True)

        table = Table(title="[bold white]Recent Intelligence[/bold white]",
                      expand=True, border_style="blue", title_justify="left")
        table.add_column("Date", style="dim cyan")
        table.add_column("Target", style="bold white")
        table.add_column("Engine Status")
        table.add_column("Risk Score")

        table.add_row("Today, 10:30", "example.com",
                      "[green]Completed[/green]", "[bold red]High (8.4)[/bold red]")
        table.add_row("Yesterday", "internal-api.local",
                      "[green]Completed[/green]", "[bold yellow]Medium (5.2)[/bold yellow]")
        table.add_row("2 Days Ago", "legacy-portal.net",
                      "[blue]Discovery...[/blue]", "[dim]Pending...[/dim]")

        watermark_art = r"""
 __   __  _    _   _       _   _     _      ____       _    
 \ \ / / | |  | | | |     | \ | |   / \    |  _ \     / \   
  \ V /  | |  | | | |     |  \| |  / _ \   | |_) |   / _ \  
   | |   | |__| | | |___  | |\  | / ___ \  |  _ <   / ___ \ 
   |_|    \____/  |_____| |_| \_|/_/   \_\ |_| \_\ /_/   \_\
        """
        watermark = Align.center(Text(watermark_art, style="dim"))

        return Group(title, Text("\n"), stats, Text("\n"), table, Text("\n\n"), watermark)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        log_view = self.query_one("#log_view", RichLog)
        title_label = self.query_one("#view_title", Label)
        save_btn = self.query_one("#save_btn", Button)

        log_view.clear()
        opt_id = event.option.id

        if opt_id in ["opt_disc", "opt_nmap", "opt_ai", "opt_full"]:
            save_btn.display = True
        else:
            save_btn.display = False

        if opt_id == "opt_dash":
            title_label.update("📊 DASHBOARD")
            log_view.write(self._build_dashboard_ui())

        elif opt_id == "opt_proj":
            title_label.update("⚙️ PROJECT SETUP")
            instructions = """
[bold white]To create a new project workspace, use the core CLI engine:[/bold white]
> [bold cyan]vulnara project create "ProjectName" "Optional Description"[/bold cyan]

[bold white]Active Workspace:[/bold white] [bold green]Default[/bold green]
[bold white]Storage Path:[/bold white]   /storage/projects/default/
[bold white]Database:[/bold white]       vulnara.db (SQLite3)
            """
            log_view.write(Align.center(Panel(Text.from_markup(
                instructions), border_style="yellow", title="Workspace Config")))

        elif opt_id == "opt_disc":
            self.active_module = "Discovery_Engine"
            title_label.update("🔍 DISCOVERY ENGINE")
            self.run_worker(self._mock_discovery(log_view), exclusive=True)

        elif opt_id == "opt_nmap":
            self.active_module = "Network_Scan"
            title_label.update("🌐 NETWORK SCANNER")
            self.run_worker(self._mock_nmap(log_view), exclusive=True)

        elif opt_id == "opt_ai":
            self.active_module = "AI_Threat_Analysis"
            title_label.update("🧠 AI THREAT ANALYSIS")
            self.run_worker(self._mock_ai_analysis(log_view), exclusive=True)

        elif opt_id == "opt_full":
            self.active_module = "Full_Report"
            title_label.update("🚀 FULL ASSESSMENT")
            self.run_worker(self._mock_full_assessment(
                log_view), exclusive=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save_btn":
            log_view = self.query_one("#log_view", RichLog)
            self.run_worker(self._trigger_report_download(
                log_view), exclusive=True)

    async def _trigger_report_download(self, log_view: RichLog) -> None:
        log_view.write(Rule(style="yellow"))
        log_view.write(
            "[bold yellow]⚙️ Compiling and formatting report data...[/bold yellow]")
        await asyncio.sleep(1)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        project_root = Path.cwd()
        reports_dir = project_root / "service_reports" / self.active_module
        file_name = f"report_{timestamp}.html"
        file_path = reports_dir / file_name

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(
                    f"<html><body><h1>Vulnara Security Report</h1></body></html>")
            log_view.write(
                f"[bold green]✔️ SUCCESS: Report saved to ->[/bold green] [bold white]{file_path}[/bold white]\n")
            log_view.write(Rule(style="green"))
        except FileNotFoundError:
            log_view.write(
                f"\n[bold red]❌ ERROR: Directory not found ->[/bold red] {reports_dir}\n")

    # command: High-impact visualization execution sequences
    async def _mock_discovery(self, log_view: RichLog) -> None:
        radar_art = r"""
        .      .     T A R G E T   L O C K E D
         \    /      [ example.com ]
          \  /       
       --- ++ ---    Initiating Passive Sensors...
          /  \       
         /    \      
        '      '     
        """
        log_view.write(Align.center(Text(radar_art, style="bold cyan")))
        log_view.write(Rule(style="cyan"))

        log_view.write(
            "[bold blue][*][/bold blue] Querying Global DNS Infrastructure... [green]OK[/green]")
        await asyncio.sleep(0.8)
        log_view.write(
            "[bold blue][*][/bold blue] Extracting WHOIS Registration Data... [green]OK[/green]")
        await asyncio.sleep(0.8)
        log_view.write(
            "[bold blue][*][/bold blue] Fingerprinting Technology Stack...    [green]OK[/green]\n")
        await asyncio.sleep(1)

        table = Table(border_style="cyan", expand=True)
        table.add_column("Asset Category", style="bold white")
        table.add_column("Extracted Value", style="bold cyan")
        table.add_row("IP Address", "104.21.55.10")
        table.add_row("Nameservers", "ns1.cloudflare.com, ns2.cloudflare.com")
        table.add_row("Server Tech", "Nginx 1.18.0 / React JS")

        log_view.write(Panel(
            table, title="[bold green]INTELLIGENCE GATHERED[/bold green]", border_style="green"))
        log_view.write(
            "\n[dim]Action: Click 'EXPORT REPORT' to preserve this intelligence.[/dim]")

    async def _mock_nmap(self, log_view: RichLog) -> None:
        net_art = r"""
           _|_      
          / | \     S C A N N I N G   N E T W O R K
         /  |  \    [ Port ranges: 1-65535 ]
        +---+---+   
        |   |   |   Engine: Nmap Advanced Stealth
        +---+---+   
        """
        log_view.write(Align.center(Text(net_art, style="bold blue")))
        log_view.write(Rule(style="blue"))

        log_view.write(
            "[dim]Injecting SYN packets...[/dim] [██████████░░░░] 75%")
        await asyncio.sleep(1)
        log_view.write(
            "[dim]Resolving service signatures...[/dim] [██████████████] 100%\n")
        await asyncio.sleep(1)

        table = Table(border_style="blue", expand=True)
        table.add_column("PORT", style="bold white")
        table.add_column("STATE", style="bold green")
        table.add_column("SERVICE", style="bold cyan")

        table.add_row("80/tcp", "OPEN", "Apache httpd 2.4.41")
        table.add_row("443/tcp", "OPEN", "nginx 1.18.0")
        table.add_row(
            "22/tcp", "[bold yellow]FILTERED[/bold yellow]", "ssh - Firewall detected")

        log_view.write(Panel(
            table, title="[bold green]NETWORK TOPOLOGY MAPPED[/bold green]", border_style="green"))

    async def _mock_ai_analysis(self, log_view: RichLog) -> None:
        ai_art = r"""
           .---.    
          /     \   N E U R A L   A N A L Y S I S
         | () () |  [ Engine: OpenRouter GPT-4 ]
          \  ^  /   
           |||||    Analyzing threat vectors...
        """
        log_view.write(Align.center(Text(ai_art, style="bold magenta")))
        log_view.write(Rule(style="magenta"))

        log_view.write("[dim]Evaluating HTTP headers...[/dim]")
        await asyncio.sleep(0.5)
        log_view.write("[dim]Correlating CVE databases...[/dim]")
        await asyncio.sleep(1)
        log_view.write(
            "[bold green]✔️ Neural processing complete.[/bold green]\n")
        await asyncio.sleep(0.5)

        summary = """[bold red]CRITICAL RISK SCORE: 8.4 / 10[/bold red]\n
[bold white]VULNERABILITY:[/bold white] Outdated Apache server (2.4.41) detected.
[bold white]IMPACT:[/bold white] Susceptible to known Path Traversal and RCE exploits.
[bold white]ACTION:[/bold white] Immediate patch to v2.4.58 recommended. Restrict port 22 access."""

        log_view.write(Panel(
            summary, title="[bold red]AI THREAT REPORT[/bold red]", border_style="red"))

    async def _mock_full_assessment(self, log_view: RichLog) -> None:
        log_view.write(
            Rule("[bold red]INITIATING AUTONOMOUS PIPELINE[/bold red]", style="red"))
        await asyncio.sleep(1)

        log_view.write(Panel(
            "[bold cyan]PHASE 1:[/bold cyan] Discovery Engine [bold green]...COMPLETED[/bold green]", border_style="cyan"))
        await asyncio.sleep(1)
        log_view.write(Panel(
            "[bold blue]PHASE 2:[/bold blue] Network Scanner [bold green]...COMPLETED[/bold green]", border_style="blue"))
        await asyncio.sleep(1)
        log_view.write(Panel(
            "[bold yellow]PHASE 3:[/bold yellow] Rules Engine [bold green]...COMPLETED[/bold green]", border_style="yellow"))
        await asyncio.sleep(1)
        log_view.write(Panel(
            "[bold magenta]PHASE 4:[/bold magenta] AI Synthesis [bold green]...COMPLETED[/bold green]", border_style="magenta"))
        await asyncio.sleep(1)

        log_view.write("\n")
        log_view.write(Panel(Align.center(
            "[bold green]✅ SYSTEM SECURED. ALL TELEMETRY COMPILED.[/bold green]"), border_style="green"))
