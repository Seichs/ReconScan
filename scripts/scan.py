class CLIInterface:
    def __init__(self):
        self.banner = """
\033[92m
| ___ \\                   /  ___|
| |_/ /___  ___ ___  _ __ \\ `--.  ___ __ _ _ __
|    // _ \\/ __/ _ \\| '_ \\ `--. \\/ __/ _` | '_ |
| |\\ \\  __/ (_| (_) | | | /\\__/ / (_| (_| | | | |
\\_| \\_\\___|\\___\\___/|_| |_|\\____/ \\___\\__,_|_| |_|

\033[91m              [:: ReconScan ::]\033[0m
\033[90m     Web Application Vulnerability Scanner\033[0m
"""

        self.commands = {
            "scan": "Run a scan against a target URL",
            "config": "Edit or view the scan configuration",
            "report": "View or generate reports",
            "exit": "Exit the program"
        }
    def display(self):
        print(self.banner)
        print("Available commands:")
        for cmd, desc in self.commands.items():
            print(f"  {cmd:<10} - {desc}")
        print("\nType a command to begin:")

    def prompt(self):
        while True:
            user_input = input("ReconScan> ").strip().lower()
            if user_input == "exit":
                print("Exiting ReconScan. Stay secure.")
                break
            elif user_input in self.commands:
                print(f"Executing '{user_input}'...")  # Hook in real logic here
            else:
                print("Unknown command.")

def main():
    cli = CLIInterface()
    cli.display()
    cli.prompt()

if __name__ == "__main__":
    main()