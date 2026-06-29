import os
from jinja2 import Environment, FileSystemLoader

class HTMLReporter:
    def __init__(self, target, scan_results):
        self.target = target
        self.scan_results = scan_results
        
    def generate(self, output_dir="reports"):
        # Make sure output directory exists
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
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
        
        with open(output_file, "w") as f:
            f.write(html_content)
            
        return os.path.abspath(output_file)
