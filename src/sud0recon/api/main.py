from fastapi import FastAPI


app = FastAPI(
    title="Sud0Recon API",
    description="REST API for Sud0Recon Scanner"
)


@app.get("/status")
async def get_status():
    return {"status": "Sud0Recon is running"}
