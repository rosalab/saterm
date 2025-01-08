# Makefile for setting up dependencies, creating a dummy file, running healthcheck, and terminate scripts

# Define variables
SCRIPT = healthcheck.sh
TERMINATE_SCRIPT = terminate.sh
LOGFILE = /var/log/system_healthcheck.log
DUMMYFILE = largefile.txt

# Default target
all: install create_dummy run terminate

# Target to install dependencies
install:
	@echo "Installing dependencies..."
	apt-get update
	DEBIAN_FRONTEND=noninteractive apt-get install -y vim cron net-tools sysstat coreutils

# Target to create the dummy file
create_dummy:
	@echo "Creating dummy file $(DUMMYFILE)..."
	@seq 1 1000000 | shuf > $(DUMMYFILE)

# Target to run the healthcheck script
run:
	@echo "Running $(SCRIPT)..."
	./$(SCRIPT)
	@echo "Removing $(DUMMYFILE) after script execution..."
	rm -f $(DUMMYFILE)

# Target to run the terminate script
terminate:
	@echo "Running $(TERMINATE_SCRIPT)..."
	./$(TERMINATE_SCRIPT)

# Target to clean logs and dummy file
clean:
	@echo "Cleaning up logs and dummy file..."
	rm -f $(LOGFILE) $(DUMMYFILE)

# Target to reset everything (clean, reinstall dependencies, and recreate dummy file)
reset: clean install create_dummy
	@echo "System reset complete."
