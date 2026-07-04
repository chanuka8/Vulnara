import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import click
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vulnara.core.database import DatabaseManager
from vulnara.core.orchestrator import ScanOrchestrator
from vulnara.core.discovery import DiscoveryEngine

PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = PROJECT_ROOT / "storage" / "vulnara.db"

console = Console()

def load_yaml(file_path: Path) -> dict:
    if not file_path.exists():
        return {}
    with open(file_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def print_banner():
    banner = r"""
   _    __      __                               
  | |  / /_  __/ /___  ____ ___________ _        
  | | / / / / / / __ \/ __ `/ ___/ __ `/         
  | |/ / /_/ / / / / / /_/ / /  / /_/ /          
  |___/\__,_/_/_/ /_/\__,_/_/   \__,_/           
                                                 
    Terminal Edition v0.1.0                      
    Authorized Security Assessment Automation    
    """
    panel = Panel(Text(banner, style="bold cyan", justify="center"), border_style="cyan")
    console.print(panel)

def print_findings_summary(result):
    console.print(f"[bold green][OK][/bold green] Findings generated: {len(result.findings)}")
    
    if result.findings:
        table = Table(title="Findings Summary", show_header=True, header_style="bold magenta")
        table.add_column("Severity", justify="left")
        table.add_column("Title", justify="left")
        table.add_column("Category", justify="left")

        color_map = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "blue"
        }

        for f in result.findings:
            sev_str = str(f.severity).upper()
            color = color_map.get(sev_str, "white")
            table.add_row(
                f"[{color}]{sev_str}[/{color}]",
                str(f.title),
                str(f.category)
            )
        
        console.print(table)
    
    console.print(f"[bold green][OK][/bold green] Evidence saved: {result.evidence_path}")
    console.print(f"[bold green][OK][/bold green] Report saved: {result.report_path}")

@click.group()
def cli():
    pass

@cli.group()
def project():
    pass

@project.command("create")
@click.argument("name")
@click.argument("description", required=False, default="")
def create_project(name: str, description: str):
    db = DatabaseManager(DB_PATH)
    try:
        proj = db.create_project(name=name, description=description)
        click.secho(f"[OK] Project created successfully: {proj.name} (ID: {proj.id})", fg="green")
    except ValueError as e:
        click.secho(f"[ERROR] {str(e)}", fg="red", err=True)
        sys.exit(1)

@cli.command("scan")
@click.argument("target_url")
@click.option("-d", "--domain", required=True)
@click.option("-p", "--profile", default="passive_recon")
@click.option("--ai", is_flag=True, default=False)
@click.option("--project", "project_name", required=False, default=None)
def run_scan(target_url: str, domain: str, profile: str, ai: bool, project_name: str):
    print_banner()
    
    db = DatabaseManager(DB_PATH)

    if project_name:
        proj = db.get_project_by_name(project_name)
        if not proj:
            click.secho(f"[ERROR] Project '{project_name}' not found. Create it first.", fg="red", err=True)
            sys.exit(1)
    else:
        proj = db.get_project_by_name("Default")
        if not proj:
            proj = db.create_project(name="Default", description="Default workspace")

    click.secho(f"[INFO] Target: {target_url}", fg="blue")
    click.secho(f"[INFO] Linked to Project: {proj.name}", fg="blue")

    scan_record = db.create_scan_record(
        project_id=proj.id,
        target_url=target_url,
        profile_name=profile
    )
    
    db.update_scan_status(scan_id=scan_record.id, status="running")

    # ---- PHASE 2: DISCOVERY ENGINE ----
    click.secho("[INFO] Starting Discovery Engine...", fg="blue")
    discovery_dir = PROJECT_ROOT / "storage" / "projects" / proj.id / "discovery"
    discovery_engine = DiscoveryEngine(target_domain=domain, output_dir=discovery_dir)
    assets = discovery_engine.run()
    click.secho(f"[OK] Discovery completed. Found {len(assets)} assets. Saved to assets.json", fg="green")
    # -----------------------------------

    settings = load_yaml(PROJECT_ROOT / "config" / "settings.yaml")
    scan_profiles = load_yaml(PROJECT_ROOT / "config" / "scan_profiles.yaml")

    orchestrator = ScanOrchestrator(
        project_root=PROJECT_ROOT,
        settings=settings,
        scan_profiles=scan_profiles
    )

    try:
        result = orchestrator.run(
            target_url=target_url,
            authorized_domain=domain,
            profile_name=profile,
            ai_enabled=ai
        )
        
        db.update_scan_status(
            scan_id=scan_record.id,
            status="completed",
            completed_at=datetime.now(timezone.utc).isoformat()
        )
        
        print_findings_summary(result)
        
    except Exception as e:
        db.update_scan_status(
            scan_id=scan_record.id,
            status="failed",
            error_message=str(e),
            completed_at=datetime.now(timezone.utc).isoformat()
        )
        click.secho(f"[ERROR] Scan failed: {str(e)}", fg="red", err=True)
        sys.exit(1)

if __name__ == "__main__":
    cli()