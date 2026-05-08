import strawberry
from typing import List, Optional
from datetime import datetime

@strawberry.type
class Agent:
    id: str
    hostname: str
    os_version: str
    last_seen: str
    status: str
    public_ip: Optional[str]

@strawberry.type
class Task:
    id: str
    agent_id: str
    command: str
    status: str
    result: Optional[str]
    created_at: str

@strawberry.type
class Query:
    @strawberry.field
    def agents(self) -> List[Agent]:
        # Placeholder for Neo4j fetch
        return [
            Agent(
                id="ghost-001",
                hostname="VICTIM-PC",
                os_version="Windows 11 Pro",
                last_seen=datetime.now().isoformat(),
                status="ALIVE",
                public_ip="1.2.3.4"
            )
        ]

    @strawberry.field
    def tasks(self, agent_id: str) -> List[Task]:
        return []

@strawberry.type
class Mutation:
    @strawberry.mutation
    def task_agent(self, agent_id: str, command: str) -> Task:
        # Placeholder for Neo4j create task
        return Task(
            id="task-123",
            agent_id=agent_id,
            command=command,
            status="PENDING",
            result=None,
            created_at=datetime.now().isoformat()
        )

schema = strawberry.Schema(query=Query, mutation=Mutation)
