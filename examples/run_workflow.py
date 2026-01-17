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
    # Replace this URL with any you'd like to analyze
    target_url = "https://example.com"
    initial_state = {"url": target_url, "page_load_result": None, "error": None}

    logger.info(f"Starting workflow for URL: {target_url}")

    # 3. Run the workflow
    try:
        # We use aconfig because the node is async
        final_state = await app.ainvoke(initial_state)

        # 4. Handle results
        if final_state.get("error"):
            logger.error(f"Workflow finished with error: {final_state['error']}")
        else:
            logger.info("Workflow completed successfully!")

        print("\n--- Final Workflow State ---")
        import json

        # Handle non-serializable objects if any, or just print pretty
        # The result might contain complex objects from MCP, so using print()
        for key, value in final_state.items():
            if key == "page_load_result" and value:
                print(f"{key}: [Result with content length {len(str(value.get('content', '')))}]")
            else:
                print(f"{key}: {value}")
        print("----------------------------\n")

    except Exception as e:
        logger.exception(f"Workflow failed to execute: {e}")


if __name__ == "__main__":
    asyncio.run(main())
