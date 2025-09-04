import sys
import os
import logging
import asyncio
from typing import List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from gscapy_web.core.nmap_scanner import run_nmap_scan
from gscapy_web.core.arp_scanner import run_arp_scan
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

# --- Helper Functions ---

async def run_scan_async(func, *args):
    """
    Asynchronous wrapper for any blocking scan function.
    """
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, func, *args)


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

        # The stream_ai_analysis function is a generator. We need to adapt it for async.
        # Running a generator in an executor is tricky. A better way is to make the core function async
        # or use a thread-safe queue. For now, we'll collect the chunks in the executor.

        # This is a simplified approach. A true async implementation of the core
        # function would be better.
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
