import os
from jinja2 import Environment, FileSystemLoader

class HTMLReporter:
    def __init__(self, target, scan_results):
        self.target = target
        self.scan_results = scan_results
        
    def generate(self, output_dir="reports"):
        # Resolve and create output directory
        output_dir = os.path.abspath(output_dir)
        try:
            os.makedirs(output_dir, exist_ok=True)
        except PermissionError:
            fallback_dir = os.path.join(os.path.expanduser("~"), ".mqtt_auditor", "reports")
            os.makedirs(fallback_dir, exist_ok=True)
            output_dir = fallback_dir
            print(f"  [!] Permission denied writing to report directory. Using fallback: {output_dir}")

        # Set up Jinja2 template loader
        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template('report.html')
        
        # Render the HTML using our scan results
        html_content = template.render(
            target=self.target,
            score=self.scan_results["overall_score"],
            rating=self.scan_results["rating"],
            findings=self.scan_results["findings"]
        )
        
        # Save file (replaces characters like colons or slashes in target IPs)
        safe_target = self.target.replace('.', '_').replace(':', '_')
        output_file = os.path.join(output_dir, f"report_{safe_target}.html")

        try:
            with open(output_file, "w") as f:
                f.write(html_content)
        except PermissionError:
            fallback_dir = os.path.join(os.path.expanduser("~"), ".mqtt_auditor", "reports")
            os.makedirs(fallback_dir, exist_ok=True)
            output_file = os.path.join(fallback_dir, f"report_{safe_target}.html")
            with open(output_file, "w") as f:
                f.write(html_content)
            print(f"  [!] Permission denied writing HTML report in default directory. Saved report to: {output_file}")

        return os.path.abspath(output_file)
