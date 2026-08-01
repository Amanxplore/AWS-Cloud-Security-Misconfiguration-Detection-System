import os
import json
import boto3
import shutil
from datetime import datetime

# -------------------------------------------------------------------------
# AWS Lambda Environment Setup
# -------------------------------------------------------------------------
# AWS Lambda's filesystem is read-only EXCEPT for the /tmp directory.
# We instruct main.py to save all generated reports to /tmp.
os.environ["RISK_ENGINE_OUTPUT_DIR"] = "/tmp"

# Now we can safely import our orchestrator
from main import run_scan

s3 = boto3.client('s3')
BUCKET = 'cloud-security-reports-mihir'

def lambda_handler(event, context):
    """
    AWS Lambda entry point.
    1. Executes the 3-phase security scan pipeline.
    2. Uploads the generated JSON and HTML reports from /tmp to S3.
    3. Cleans up /tmp to prevent storage exhaustion on warm invocations.
    """
    print("Starting Cloud Misconfiguration Detection System (Lambda Edition)...")
    
    try:
        # 1. Run the entire pipeline (Scanners -> Risk Engine -> HTML Generation)
        # We don't skip scoring, and we run all services.
        scan_report, risk_report = run_scan(services=None, skip_scoring=False)
        
        uploaded_files = []
        
        # 2. Upload all generated reports from /tmp to S3
        for sub_dir in ["reports", "findings", "risk"]:
            local_dir = f"/tmp/{sub_dir}"
            if not os.path.exists(local_dir):
                continue
                
            for filename in os.listdir(local_dir):
                local_file_path = os.path.join(local_dir, filename)
                if os.path.isfile(local_file_path):
                    # S3 Key structure: reports/filename.html
                    s3_key = f"{sub_dir}/{filename}"
                    
                    print(f"Uploading {filename} to s3://{BUCKET}/{s3_key}")
                    s3.upload_file(local_file_path, BUCKET, s3_key)
                    uploaded_files.append(s3_key)
                    
            # 3. Clean up the /tmp subdirectory after uploading
            shutil.rmtree(local_dir, ignore_errors=True)

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Scan and Risk Scoring completed successfully.',
                'uploaded_files': uploaded_files
            })
        }
        
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Scan failed',
                'error': str(e)
            })
        }

if __name__ == "__main__":
    # Local testing mock
    print("Running local mock of lambda_handler...")
    print(json.dumps(lambda_handler(None, None), indent=4))