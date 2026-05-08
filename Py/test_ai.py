import asyncio
import os
from dotenv import load_dotenv
from app.core.llm_commander import hive_mind


async def test():
    print(f"Model Name in Code: {hive_mind.model.model_name}")
    print("Testing connection...")
    response = await hive_mind.consult_strategic_advisor("ما هو وضع النظام الراهن؟")
    print(f"Response:\n{response}")


if __name__ == "__main__":
    asyncio.run(test())
