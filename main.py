import argparse
import sys
import os
import toml


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))


from src.core import ReportService
from src.gui import DomainAnalyzerGUI
from src.exceptions import ReportGenerationError, ToolNotFoundError, SubprocessFailedError
# ADDED: Import the mock data generator
from src.mock_data_generator import generate_mock_data

def main():
    """Main function to handle CLI vs GUI mode."""
    parser = argparse.ArgumentParser(description="Analyze a domain and generate a security report using an LLM.",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("domain", nargs='?', help="The domain or IP to analyze (CLI mode only).")
    parser.add_argument("-g", "--gui", action="store_true", help="Launch the graphical user interface.")
    # ADDED: New argument for mock data generation
    parser.add_argument("--mock-data", type=str, nargs='?', const="secure", 
                        help="Generate a report from mock data instead of a live scan. "
                             "Optional: provide a scenario (e.g., 'secure', 'vulnerable'). "
                             "Defaults to 'secure' if no scenario is specified.")
    args = parser.parse_args()

    # Load configuration from config.toml
    try:
        config = toml.load("config.toml")
    except FileNotFoundError:
        print("Error: config.toml file not found. Please create it with the required settings.")
        sys.exit(1)
    except toml.TomlDecodeError as e:
        print(f"Error: Could not parse config.toml. Please check its syntax: {e}")
        sys.exit(1)

    if args.gui:
        # Pass the entire config dictionary to the GUI
        app = DomainAnalyzerGUI(config)
        app.mainloop()
    # ADDED: New elif block to handle the --mock-data argument
    elif args.mock_data:
        scenario = args.mock_data if args.mock_data else "secure"
        print(f"Generating mock security report for scenario: {scenario}")
        try:
            # Generate the mock data using the new function
            mock_data = generate_mock_data(scenario)
            
            # Pass the mock data directly to the report service
            service = ReportService(config)
            report = service.generate_security_report(mock_data=mock_data)

            print("\n" + "="*50)
            print("MOCK SECURITY REPORT GENERATED")
            print("="*50 + "\n")
            print(report)
            print("\n" + "="*50)
            print(f"Note: This report is based on mock data and was not saved to a file.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
    elif args.domain:
        print(f"Starting security analysis for target: {args.domain}")
        try:
            # Pass the entire config dictionary to the ReportService
            service = ReportService(config)
            
            report = service.generate_security_report(domain=args.domain)
            
            print("\n" + "="*50)
            print("SECURITY REPORT GENERATED")
            print("="*50 + "\n")
            print(report)
            print("\n" + "="*50)
            
            reports_dir = config.get("paths", {}).get("reports_dir", "reports")
            print(f"Report also saved to {os.path.join(reports_dir, f'{args.domain}_security_report.txt')}")
        except (ReportGenerationError, ToolNotFoundError, SubprocessFailedError) as e:
            print(f"An error occurred: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

