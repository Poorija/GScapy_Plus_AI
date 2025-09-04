import sys
import os
import logging
import asyncio
import json
from typing import List, Optional, Dict, Any, AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from gscapy_web.core.nmap_scanner import run_nmap_scan
from gscapy_web.core.arp_scanner import run_arp_scan
from gscapy_web.core.port_scanner import scan_ports
from gscapy_web.core.ping_sweeper import run_ping_sweep
from gscapy_web.core.traceroute import run_traceroute
from gscapy_web.core.ai_analyzer import stream_ai_analysis, get_ai_settings
from fastapi.responses import StreamingResponse

# Basic logging configuration
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="GScapy Web API",
    description="An API for running network scanning and analysis tools.",
    version="1.0.0"
)

# --- Models ---

class NmapScanRequest(BaseModel):
    target: str
    ports: str | None = None
    arguments: list[str] = []

class NmapScanResponse(BaseModel):
    raw_output: str
    xml_output: str | None

class ArpScanRequest(BaseModel):
    target_network: str
    iface: str | None = None

class ArpHost(BaseModel):
    ip: str
    mac: str
    vendor: str

class PortScanRequest(BaseModel):
    target: str
    ports: str
    scan_type: str = "TCP SYN Scan"
    timeout: int = 1
    use_fragments: bool = False

class PortScanResult(BaseModel):
    port: int
    protocol: str
    state: str
    service: str

class PingSweepRequest(BaseModel):
    target_network: str
    probe_type: str = "ICMP Echo"
    ports: Optional[str] = "80,443"
    timeout: int = 1
    num_threads: int = 20

class PingSweepResult(BaseModel):
    ip: str
    status: str

class TracerouteRequest(BaseModel):
    target: str
    max_hops: int = 30
    timeout: int = 2

# --- Helper Functions ---

async def run_scan_async(func, *args, **kwargs):
    """
    Asynchronous wrapper for any blocking scan function.
    Supports both positional and keyword arguments.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))


# --- API Endpoints ---

@app.get("/")
def read_root():
    return {"message": "Welcome to the GScapy Web API"}

@app.post("/api/nmap", response_model=NmapScanResponse)
async def perform_nmap_scan(request: NmapScanRequest):
    """
    Performs an Nmap scan with the specified parameters.
    """
    if not request.target:
        raise HTTPException(status_code=400, detail="Target is a required field.")

    command = ["nmap"] + request.arguments + [request.target]
    if request.ports:
        command.extend(["-p", request.ports])

    logging.info(f"API received Nmap scan request: {' '.join(command)}")

    try:
        raw_output, xml_output = await run_scan_async(run_nmap_scan, command)
        if raw_output is None:
            raise HTTPException(status_code=500, detail="Nmap scan failed to run.")
        return NmapScanResponse(raw_output=raw_output, xml_output=xml_output)
    except Exception as e:
        logging.error(f"An error occurred during the Nmap scan API call: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"An internal server error occurred: {str(e)}")

@app.post("/api/arp", response_model=List[ArpHost])
async def perform_arp_scan(request: ArpScanRequest):
    """
    Performs an ARP scan on the specified network.
    """
    if not request.target_network:
        raise HTTPException(status_code=400, detail="Target network is a required field.")

    logging.info(f"API received ARP scan request for network: {request.target_network}")

    try:
        results = await run_scan_async(run_arp_scan, request.target_network, request.iface)
        return results
    except Exception as e:
        logging.error(f"An error occurred during the ARP scan API call: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"An internal server error occurred: {str(e)}")

@app.post("/api/port_scan", response_model=List[PortScanResult])
async def perform_port_scan(request: PortScanRequest):
    """
    Performs a Scapy-based port scan on the specified target.
    """
    if not request.target:
        raise HTTPException(status_code=400, detail="Target is a required field.")
    if not request.ports:
        raise HTTPException(status_code=400, detail="Ports are a required field.")

    logging.info(f"API received port scan request for target: {request.target} on ports {request.ports}")

    try:
        results = await run_scan_async(
            scan_ports,
            request.target,
            request.ports,
            scan_type=request.scan_type,
            timeout=request.timeout,
            use_fragments=request.use_fragments
        )
        return results
    except Exception as e:
        logging.error(f"An error occurred during the port scan API call: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"An internal server error occurred: {str(e)}")

@app.post("/api/ping_sweep", response_model=List[PingSweepResult])
async def perform_ping_sweep(request: PingSweepRequest):
    """
    Performs a ping sweep to discover active hosts on a network.
    """
    if not request.target_network:
        raise HTTPException(status_code=400, detail="Target network is a required field.")

    logging.info(f"API received ping sweep request for network: {request.target_network}")

    ports_list = []
    if request.ports:
        try:
            ports_list = [int(p.strip()) for p in request.ports.split(',')]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid format for ports. Must be comma-separated integers.")

    try:
        results = await run_scan_async(
            run_ping_sweep,
            target_network=request.target_network,
            probe_type=request.probe_type,
            ports=ports_list,
            timeout=request.timeout,
            num_threads=request.num_threads
        )
        return results
    except Exception as e:
        logging.error(f"An error occurred during the ping sweep API call: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"An internal server error occurred: {str(e)}")

@app.post("/api/traceroute")
async def stream_traceroute(req: TracerouteRequest, http_request: Request):
    """
    Performs a traceroute and streams the results back to the client.
    """
    if not req.target:
        raise HTTPException(status_code=400, detail="Target is a required field.")

    logging.info(f"API received traceroute request for target: {req.target}")

    async def event_generator():
        # Running the blocking generator in an executor is complex.
        # A simpler way for this use case is to create a queue and a separate
        # thread to populate it, which the async generator can then read from.
        q = asyncio.Queue()

        def traceroute_thread():
            try:
                for hop_result in run_traceroute(req.target, req.max_hops, req.timeout):
                    q.put_nowait(hop_result)
            except Exception as e:
                logging.error(f"Error in traceroute thread: {e}", exc_info=True)
                q.put_nowait({"type": "error", "message": str(e)})
            finally:
                q.put_nowait(None) # Signal completion

        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, traceroute_thread)

        while True:
            # Check if the client has disconnected
            if await http_request.is_disconnected():
                logging.warning("Client disconnected from traceroute stream.")
                break

            result = await q.get()
            if result is None:
                break

            # SSE format: data: <json_string>\n\n
            yield f"data: {json.dumps(result)}\n\n"
            await asyncio.sleep(0.01) # Small sleep to yield control

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# --- AI Assistant Endpoint ---

class ChatRequest(BaseModel):
    prompt: str

async def ai_response_generator(prompt: str):
    """
    Generator function that gets AI settings and streams the response.
    """
    try:
        # This is a blocking call, so run it in an executor
        settings = await run_scan_async(get_ai_settings)
        if not settings:
            yield "Error: AI settings are not configured or failed to load."
            return

        for chunk in stream_ai_analysis(prompt, settings):
            yield chunk
            await asyncio.sleep(0.01) # Yield control to the event loop

    except Exception as e:
        logging.error(f"Error in AI response generator: {e}", exc_info=True)
        yield f"Error: Could not get AI response. {str(e)}"

@app.post("/api/ai/chat")
async def chat_with_ai(request: ChatRequest):
    """
    Handles a chat request and streams the AI's response back.
    """
    if not request.prompt:
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")

    return StreamingResponse(ai_response_generator(request.prompt), media_type="text/event-stream")
