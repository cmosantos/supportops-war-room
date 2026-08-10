import asyncio

from agents import set_trace_processors
from langsmith.integrations.openai_agents_sdk import (
    OpenAIAgentsTracingProcessor,
)

from supportops_warroom_v4 import main


async def run():
    processor = OpenAIAgentsTracingProcessor()

    set_trace_processors([processor])

    try:
        await main()
    finally:
        force_flush = getattr(processor, "force_flush", None)

        if force_flush is not None:
            maybe_awaitable = force_flush()

            if hasattr(maybe_awaitable, "__await__"):
                await maybe_awaitable


if __name__ == "__main__":
    asyncio.run(run())