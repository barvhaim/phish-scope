import asyncio
import logging
from phish_scope.workflow.graph import build_graph

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


async def main():
    # 1. Build the graph
    app = build_graph()

    # 2. Define the initial state
    target_url = "https://news.ycombinator.com/"
    initial_state = {
        "workflow_id": "test_workflow_001",
        "url": target_url,
        "output_dir": "./reports/test_001",
        "page_load_result": None,
        "network_log": None,
        "dom_findings": None,
        "js_findings": None,
        "network_findings": None,
        "ai_findings": None,
        "report_path": None,
        "status": "pending",
        "start_time": None,
        "end_time": None,
        "error": None
    }

    logger.info(f"Starting workflow for URL: {target_url}")

    # 3. Run the workflow
    try:
        final_state = await app.ainvoke(initial_state)

        # 4. Handle results
        if final_state.get("error"):
            logger.error(f"Workflow finished with error: {final_state['error']}")
        else:
            logger.info("Workflow completed successfully!")
            print(f"Report generated at: {final_state.get('report_path')}")

        print("\n--- Final Workflow State Findings ---")
        findings = {
            "dom": bool(final_state.get("dom_findings")),
            "js": bool(final_state.get("js_findings")),
            "network": bool(final_state.get("network_findings")),
            "ai": bool(final_state.get("ai_findings")),
        }
        print(f"Findings captured: {findings}")
        print("----------------------------\n")

    except Exception as e:
        logger.exception(f"Workflow failed to execute: {e}")


if __name__ == "__main__":
    asyncio.run(main())
