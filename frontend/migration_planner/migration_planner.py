import json
import networkx as nx
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import anthropic
from datetime import datetime, timedelta

class MigrationStrategy(Enum):
    HYBRID = "hybrid"  # Run both old and new crypto in parallel
    PHASED = "phased"  # Gradual component-by-component migration
    BIG_BANG = "big_bang"  # Switch everything at once
    CANARY = "canary"  # Test with small percentage first

@dataclass
class CryptoComponent:
    component_id: str
    name: str
    current_algorithm: str
    target_algorithm: str
    dependencies: List[str] = field(default_factory=list)
    risk_level: str = "medium"
    estimated_effort_hours: int = 0
    priority: int = 0

@dataclass
class MigrationPhase:
    phase_id: str
    name: str
    components: List[str]
    duration_days: int
    prerequisites: List[str] = field(default_factory=list)
    rollback_plan: str = ""
    testing_requirements: List[str] = field(default_factory=list)

@dataclass
class MigrationPlan:
    plan_id: str
    strategy: MigrationStrategy
    phases: List[MigrationPhase]
    total_duration_days: int
    estimated_cost: float
    risk_assessment: Dict[str, Any]
    success_criteria: List[str]
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

class MigrationPlanner:
    def __init__(self, api_key: str):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = "claude-sonnet-4-20250514"
        self.dependency_graph = nx.DiGraph()
    
    def analyze_dependencies(self, components: List[CryptoComponent]) -> nx.DiGraph:
        """Build dependency graph of crypto components"""
        graph = nx.DiGraph()
        
        for component in components:
            graph.add_node(component.component_id, data=component)
            for dep in component.dependencies:
                graph.add_edge(dep, component.component_id)
        
        self.dependency_graph = graph
        return graph
    
    def calculate_migration_order(self) -> List[str]:
        """Determine optimal migration order using topological sort"""
        try:
            return list(nx.topological_sort(self.dependency_graph))
        except nx.NetworkXError:
            # If there's a cycle, use best-effort ordering
            return list(self.dependency_graph.nodes())
    
    async def generate_migration_plan(
        self,
        components: List[CryptoComponent],
        strategy: MigrationStrategy,
        constraints: Dict[str, Any]
    ) -> MigrationPlan:
        """Generate comprehensive migration plan using AI"""
        
        # Build dependency graph
        self.analyze_dependencies(components)
        migration_order = self.calculate_migration_order()
        
        # Prepare context for AI
        context = {
            "components": [asdict(c) for c in components],
            "migration_order": migration_order,
            "strategy": strategy.value,
            "constraints": constraints,
            "total_components": len(components)
        }
        
        prompt = f"""
You are an expert in post-quantum cryptography migration planning. Analyze this system and create a detailed migration plan.

System Context:
{json.dumps(context, indent=2)}

Create a migration plan that includes:
1. Multiple phases with specific components to migrate in each
2. Duration estimates for each phase
3. Risk assessment and mitigation strategies
4. Rollback plans for each phase
5. Testing requirements
6. Success criteria

Consider:
- Dependencies between components
- Backwards compatibility requirements
- Production stability requirements from constraints
- Risk levels of different components
- {strategy.value} migration strategy

Respond with a JSON object containing:
{{
  "phases": [
    {{
      "phase_id": "phase_1",
      "name": "Phase name",
      "components": ["component_ids"],
      "duration_days": 14,
      "prerequisites": [],
      "rollback_plan": "Detailed rollback procedure",
      "testing_requirements": ["Test 1", "Test 2"]
    }}
  ],
  "total_duration_days": 90,
  "estimated_cost": 150000,
  "risk_assessment": {{
    "overall_risk": "medium",
    "key_risks": ["Risk 1", "Risk 2"],
    "mitigation_strategies": ["Strategy 1", "Strategy 2"]
  }},
  "success_criteria": ["Criterion 1", "Criterion 2"]
}}
"""
        
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=8000,
                system="You are a post-quantum cryptography migration expert. Provide detailed, actionable migration plans in JSON format.",
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = message.content[0].text
            
            # Extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                plan_data = json.loads(response_text[json_start:json_end])
            else:
                plan_data = json.loads(response_text)
            
            # Convert to MigrationPlan object
            phases = [
                MigrationPhase(**phase_dict)
                for phase_dict in plan_data["phases"]
            ]
            
            plan = MigrationPlan(
                plan_id=f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                strategy=strategy,
                phases=phases,
                total_duration_days=plan_data["total_duration_days"],
                estimated_cost=plan_data["estimated_cost"],
                risk_assessment=plan_data["risk_assessment"],
                success_criteria=plan_data["success_criteria"]
            )
            
            return plan
            
        except Exception as e:
            print(f"Error generating migration plan: {e}")
            # Return basic fallback plan
            return self._generate_fallback_plan(components, strategy)
    
    def _generate_fallback_plan(
        self,
        components: List[CryptoComponent],
        strategy: MigrationStrategy
    ) -> MigrationPlan:
        """Generate basic fallback plan if AI fails"""
        
        migration_order = self.calculate_migration_order()
        
        # Split into 3 phases
        components_per_phase = len(migration_order) // 3 + 1
        phases = []
        
        for i in range(0, len(migration_order), components_per_phase):
            phase_components = migration_order[i:i+components_per_phase]
            phases.append(MigrationPhase(
                phase_id=f"phase_{i//components_per_phase + 1}",
                name=f"Migration Phase {i//components_per_phase + 1}",
                components=phase_components,
                duration_days=14,
                prerequisites=[f"phase_{i//components_per_phase}"] if i > 0 else [],
                rollback_plan="Restore from backup",
                testing_requirements=["Unit tests", "Integration tests", "Performance tests"]
            ))
        
        return MigrationPlan(
            plan_id=f"fallback_plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            strategy=strategy,
            phases=phases,
            total_duration_days=len(phases) * 14,
            estimated_cost=100000.0,
            risk_assessment={
                "overall_risk": "medium",
                "key_risks": ["Production downtime", "Compatibility issues"],
                "mitigation_strategies": ["Thorough testing", "Gradual rollout"]
            },
            success_criteria=["All components migrated", "No security issues", "Performance maintained"]
        )
    
    async def optimize_plan(self, plan: MigrationPlan, feedback: str) -> MigrationPlan:
        """Optimize existing plan based on feedback"""
        
        prompt = f"""
Review and optimize this migration plan based on the feedback provided.

Current Plan:
{json.dumps(asdict(plan), indent=2)}

Feedback:
{feedback}

Provide an improved plan addressing the feedback while maintaining all safety requirements.
Respond with complete updated plan in JSON format.
"""
        
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=8000,
                system="You are a post-quantum cryptography migration expert. Optimize migration plans based on feedback.",
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = message.content[0].text
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                plan_data = json.loads(response_text[json_start:json_end])
                
                phases = [MigrationPhase(**p) for p in plan_data["phases"]]
                
                return MigrationPlan(
                    plan_id=f"{plan.plan_id}_optimized",
                    strategy=MigrationStrategy(plan_data.get("strategy", plan.strategy.value)),
                    phases=phases,
                    total_duration_days=plan_data["total_duration_days"],
                    estimated_cost=plan_data["estimated_cost"],
                    risk_assessment=plan_data["risk_assessment"],
                    success_criteria=plan_data["success_criteria"]
                )
            else:
                return plan
                
        except Exception as e:
            print(f"Error optimizing plan: {e}")
            return plan
    
    def export_plan(self, plan: MigrationPlan, format: str = "json") -> str:
        """Export plan in various formats"""
        
        if format == "json":
            return json.dumps(asdict(plan), indent=2)
        elif format == "markdown":
            return self._plan_to_markdown(plan)
        else:
            return json.dumps(asdict(plan))
    
    def _plan_to_markdown(self, plan: MigrationPlan) -> str:
        """Convert plan to markdown format"""
        
        md = f"""# Post-Quantum Cryptography Migration Plan

**Plan ID:** {plan.plan_id}
**Strategy:** {plan.strategy.value}
**Total Duration:** {plan.total_duration_days} days
**Estimated Cost:** ${plan.estimated_cost:,.2f}
**Created:** {plan.created_at}

## Risk Assessment

**Overall Risk:** {plan.risk_assessment.get('overall_risk', 'N/A')}

### Key Risks
"""
        for risk in plan.risk_assessment.get('key_risks', []):
            md += f"- {risk}\n"
        
        md += "\n### Mitigation Strategies\n"
        for strategy in plan.risk_assessment.get('mitigation_strategies', []):
            md += f"- {strategy}\n"
        
        md += "\n## Migration Phases\n\n"
        
        for i, phase in enumerate(plan.phases, 1):
            md += f"### Phase {i}: {phase.name}\n\n"
            md += f"**Duration:** {phase.duration_days} days\n"
            md += f"**Components:** {', '.join(phase.components)}\n\n"
            
            if phase.prerequisites:
                md += f"**Prerequisites:** {', '.join(phase.prerequisites)}\n\n"
            
            md += "**Testing Requirements:**\n"
            for test in phase.testing_requirements:
                md += f"- {test}\n"
            
            md += f"\n**Rollback Plan:** {phase.rollback_plan}\n\n"
        
        md += "## Success Criteria\n\n"
        for criterion in plan.success_criteria:
            md += f"- {criterion}\n"
        
        return md


# Example usage
async def main():
    API_KEY = "your-api-key-here"
    
    planner = MigrationPlanner(API_KEY)
    
    # Define components to migrate
    components = [
        CryptoComponent(
            component_id="auth_service",
            name="Authentication Service",
            current_algorithm="RSA-2048",
            target_algorithm="Kyber-1024",
            dependencies=[],
            risk_level="critical",
            estimated_effort_hours=80,
            priority=1
        ),
        CryptoComponent(
            component_id="api_gateway",
            name="API Gateway",
            current_algorithm="ECDSA-P256",
            target_algorithm="Dilithium-5",
            dependencies=["auth_service"],
            risk_level="high",
            estimated_effort_hours=60,
            priority=2
        ),
        CryptoComponent(
            component_id="data_encryption",
            name="Data Encryption Layer",
            current_algorithm="AES-256-GCM",
            target_algorithm="AES-256-GCM",
            dependencies=[],
            risk_level="low",
            estimated_effort_hours=20,
            priority=3
        ),
    ]
    
    constraints = {
        "max_downtime_minutes": 30,
        "backwards_compatible": True,
        "budget": 200000,
        "team_size": 5
    }
    
    # Generate plan
    plan = await planner.generate_migration_plan(
        components,
        MigrationStrategy.HYBRID,
        constraints
    )
    
    # Export to markdown
    markdown_plan = planner.export_plan(plan, format="markdown")
    
    print(markdown_plan)
    
    # Save to file
    with open("migration_plan.md", "w") as f:
        f.write(markdown_plan)
    
    print("\n✓ Migration plan generated and saved to migration_plan.md")


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
