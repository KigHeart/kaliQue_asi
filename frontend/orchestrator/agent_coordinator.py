import asyncio
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import anthropic
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

class AgentRole(Enum):
    ANALYZER = "crypto_analyzer"
    PLANNER = "migration_planner"
    EXECUTOR = "migration_executor"
    VALIDATOR = "security_validator"
    MONITOR = "deployment_monitor"

@dataclass
class AgentTask:
    task_id: str
    role: AgentRole
    description: str
    priority: int
    dependencies: List[str]
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None

@dataclass
class MigrationContext:
    project_name: str
    current_crypto: List[str]
    target_crypto: List[str]
    scale: str
    constraints: Dict[str, Any]

class Agent:
    def __init__(self, role: AgentRole, api_key: str):
        self.role = role
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-sonnet-4-20250514"
        
    async def execute_task(self, task: AgentTask, context: MigrationContext) -> Dict[str, Any]:
        """Execute a task using Claude with role-specific system prompt"""
        
        system_prompts = {
            AgentRole.ANALYZER: """You are a cryptography analysis agent. Analyze existing 
            cryptographic implementations and identify vulnerabilities to quantum attacks. 
            Provide detailed technical analysis.""",
            
            AgentRole.PLANNER: """You are a migration planning agent. Create comprehensive 
            migration strategies for transitioning to post-quantum cryptography. Consider 
            performance, compatibility, and risk factors.""",
            
            AgentRole.EXECUTOR: """You are a migration execution agent. Generate specific 
            code changes and implementation steps for PQC migration. Provide concrete, 
            actionable steps.""",
            
            AgentRole.VALIDATOR: """You are a security validation agent. Verify the security 
            and correctness of PQC implementations. Identify potential issues.""",
            
            AgentRole.MONITOR: """You are a deployment monitoring agent. Track migration 
            progress, identify issues, and recommend adjustments."""
        }
        
        prompt = f"""
Context: {json.dumps(asdict(context), indent=2)}

Task: {task.description}

Analyze this migration task and provide:
1. Detailed analysis
2. Specific recommendations
3. Risk assessment
4. Implementation steps (if applicable)

Respond in JSON format.
"""
        
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                system=system_prompts[self.role],
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = message.content[0].text
            
            # Try to parse as JSON, fallback to structured dict
            try:
                result = json.loads(response_text)
            except json.JSONDecodeError:
                result = {
                    "analysis": response_text,
                    "agent_role": self.role.value,
                    "task_id": task.task_id
                }
            
            return result
            
        except Exception as e:
            console.print(f"[red]Error in agent {self.role.value}: {str(e)}[/red]")
            return {"error": str(e), "agent_role": self.role.value}

class AgentCoordinator:
    def __init__(self, api_key: str):
        self.agents: Dict[AgentRole, Agent] = {}
        self.task_queue: List[AgentTask] = []
        self.completed_tasks: Dict[str, AgentTask] = {}
        self.api_key = api_key
        
        # Initialize agents
        for role in AgentRole:
            self.agents[role] = Agent(role, api_key)
    
    def add_task(self, task: AgentTask):
        """Add a task to the queue"""
        self.task_queue.append(task)
        console.print(f"[green]Added task:[/green] {task.task_id} ({task.role.value})")
    
    def can_execute_task(self, task: AgentTask) -> bool:
        """Check if task dependencies are met"""
        if not task.dependencies:
            return True
        return all(dep in self.completed_tasks for dep in task.dependencies)
    
    async def execute_tasks(self, context: MigrationContext):
        """Execute all tasks respecting dependencies"""
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            while self.task_queue:
                # Find executable tasks
                executable = [t for t in self.task_queue if self.can_execute_task(t)]
                
                if not executable:
                    console.print("[red]Dependency deadlock detected![/red]")
                    break
                
                # Execute tasks concurrently
                tasks_to_execute = []
                for task in executable:
                    self.task_queue.remove(task)
                    task.status = "running"
                    
                    progress_task = progress.add_task(
                        f"Executing {task.task_id}...", 
                        total=None
                    )
                    
                    agent = self.agents[task.role]
                    tasks_to_execute.append((task, agent, progress_task))
                
                # Execute concurrently
                results = await asyncio.gather(*[
                    self._execute_with_progress(agent, task, progress, prog_task)
                    for task, agent, prog_task in tasks_to_execute
                ])
                
                # Update completed tasks
                for task, result in zip([t[0] for t in tasks_to_execute], results):
                    task.status = "completed"
                    task.result = result
                    self.completed_tasks[task.task_id] = task
                    console.print(f"[green]✓[/green] Completed: {task.task_id}")
    
    async def _execute_with_progress(self, agent: Agent, task: AgentTask, 
                                     progress: Progress, progress_task):
        """Execute task and update progress"""
        result = await agent.execute_task(task, context)
        progress.update(progress_task, completed=True)
        return result
    
    def get_results(self) -> Dict[str, Any]:
        """Get all task results"""
        return {
            task_id: {
                "role": task.role.value,
                "status": task.status,
                "result": task.result
            }
            for task_id, task in self.completed_tasks.items()
        }

# Example usage
async def main():
    API_KEY = "your-api-key-here"  # Replace with actual key
    
    coordinator = AgentCoordinator(API_KEY)
    
    context = MigrationContext(
        project_name="ProductionAPI",
        current_crypto=["RSA-2048", "ECDSA-P256", "AES-256-GCM"],
        target_crypto=["Kyber-1024", "Dilithium-5", "AES-256-GCM"],
        scale="production",
        constraints={"downtime_limit": "< 5min", "backwards_compatible": True}
    )
    
    # Create task pipeline
    tasks = [
        AgentTask(
            task_id="analyze_001",
            role=AgentRole.ANALYZER,
            description="Analyze current RSA and ECDSA usage patterns",
            priority=1,
            dependencies=[]
        ),
        AgentTask(
            task_id="plan_001",
            role=AgentRole.PLANNER,
            description="Create migration plan for Kyber KEM integration",
            priority=2,
            dependencies=["analyze_001"]
        ),
        AgentTask(
            task_id="execute_001",
            role=AgentRole.EXECUTOR,
            description="Generate code for hybrid RSA/Kyber implementation",
            priority=3,
            dependencies=["plan_001"]
        ),
        AgentTask(
            task_id="validate_001",
            role=AgentRole.VALIDATOR,
            description="Validate security of hybrid implementation",
            priority=4,
            dependencies=["execute_001"]
        )
    ]
    
    for task in tasks:
        coordinator.add_task(task)
    
    await coordinator.execute_tasks(context)
    
    results = coordinator.get_results()
    console.print("\n[bold cyan]Migration Results:[/bold cyan]")
    console.print(json.dumps(results, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
