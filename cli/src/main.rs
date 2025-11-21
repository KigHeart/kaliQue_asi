use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;
use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Parser)]
#[command(name = "kalique")]
#[command(about = "kaliQue_asi - Post-Quantum Cryptography Migration System", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a codebase for cryptographic usage
    Analyze {
        /// Path to the directory to analyze
        #[arg(short, long)]path: PathBuf,
        
        /// Output format (json, markdown, summary)
        #[arg(short, long, default_value = "summary")]
        format: String,
        
        /// Save report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// Generate post-quantum cryptographic keys
    Keygen {
        /// Algorithm (kyber, dilithium)
        #[arg(short, long)]
        algorithm: String,
        
        /// Key identifier
        #[arg(short, long)]
        id: String,
        
        /// Output directory for keys
        #[arg(short, long)]
        output: PathBuf,
    },
    
    /// Generate migration plan
    Plan {
        /// Path to analysis report
        #[arg(short, long)]
        report: PathBuf,
        
        /// Migration strategy (hybrid, phased, big-bang, canary)
        #[arg(short, long, default_value = "hybrid")]
        strategy: String,
        
        /// Output file for migration plan
        #[arg(short, long)]
        output: PathBuf,
    },
    
    /// Test PQC operations
    Test {
        /// Test type (kem, signature, all)
        #[arg(short, long, default_value = "all")]
        test_type: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    println!("{}", "🔐 kaliQue_asi - Post-Quantum Cryptography Migration System".bright_cyan().bold());
    println!("{}\n", "━".repeat(60).bright_black());
    
    match cli.command {
        Commands::Analyze { path, format, output } => {
            analyze_command(path, format, output).await?;
        }
        Commands::Keygen { algorithm, id, output } => {
            keygen_command(algorithm, id, output).await?;
        }
        Commands::Plan { report, strategy, output } => {
            plan_command(report, strategy, output).await?;
        }
        Commands::Test { test_type } => {
            test_command(test_type).await?;
        }
    }
    
    Ok(())
}

async fn analyze_command(path: PathBuf, format: String, output: Option<PathBuf>) -> Result<()> {
    println!("{} Analyzing codebase at: {}", "📊".bright_yellow(), path.display());
    
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap()
    );
    pb.set_message("Scanning files...");
    
    let analyzer = crypto_analyzer::CryptoAnalyzer::new();
    let report = analyzer.analyze_directory(&path)?;
    
    pb.finish_with_message("Analysis complete!");
    
    println!("\n{}", "📋 Analysis Report".bright_green().bold());
    println!("{}", "─".repeat(60).bright_black());
    println!("Files scanned: {}", report.total_files_scanned.to_string().bright_white().bold());
    println!("Crypto usages found: {}", report.crypto_usages.len().to_string().bright_white().bold());
    
    println!("\n{}", "🔍 Algorithm Summary:".bright_blue());
    for (algo, count) in &report.algorithm_summary {
        println!("  {} {}: {}", "•".bright_black(), algo.bright_white(), count.to_string().bright_yellow());
    }
    
    println!("\n{}", "⚠️  Risk Summary:".bright_red());
    for (risk, count) in &report.risk_summary {
        let color = match risk {
            crypto_analyzer::RiskLevel::Critical => "red",
            crypto_analyzer::RiskLevel::High => "yellow",
            crypto_analyzer::RiskLevel::Medium => "blue",
            crypto_analyzer::RiskLevel::Low => "green",
        };
        println!("  {} {:?}: {}", "•".bright_black(), format!("{:?}", risk).color(color), count.to_string().bright_white().bold());
    }
    
    println!("\n{}", "💡 Recommendations:".bright_magenta());
    for (i, rec) in report.recommendations.iter().enumerate() {
        println!("  {}. {}", (i + 1).to_string().bright_black(), rec);
    }
    
    // Save output if requested
    if let Some(output_path) = output {
        let content = match format.as_str() {
            "json" => serde_json::to_string_pretty(&report)?,
            "markdown" => format_report_markdown(&report),
            _ => serde_json::to_string_pretty(&report)?,
        };
        
        std::fs::write(&output_path, content)?;
        println!("\n{} Report saved to: {}", "✓".bright_green(), output_path.display());
    }
    
    Ok(())
}

async fn keygen_command(algorithm: String, id: String, output: PathBuf) -> Result<()> {
    println!("{} Generating {} keys...", "🔑".bright_yellow(), algorithm.bright_white().bold());
    
    let mut engine = pqc_engine::PQCEngine::new();
    
    let keypair = match algorithm.to_lowercase().as_str() {
        "kyber" => {
            println!("  Algorithm: Kyber-1024 (ML-KEM)");
            engine.generate_kyber_keypair(id.clone())?
        }
        "dilithium" => {
            println!("  Algorithm: Dilithium-5 (ML-DSA)");
            engine.generate_dilithium_keypair(id.clone())?
        }
        _ => anyhow::bail!("Unknown algorithm: {}. Use 'kyber' or 'dilithium'", algorithm),
    };
    
    // Save keys
    std::fs::create_dir_all(&output)?;
    let pub_key_path = output.join(format!("{}_public.key", id));
    let sec_key_path = output.join(format!("{}_secret.key", id));
    
    std::fs::write(&pub_key_path, &keypair.public_key)?;
    std::fs::write(&sec_key_path, &keypair.secret_key)?;
    
    println!("\n{}", "✓ Keys generated successfully!".bright_green().bold());
    println!("  Public key: {} ({} bytes)", pub_key_path.display(), keypair.public_key.len());
    println!("  Secret key: {} ({} bytes)", sec_key_path.display(), keypair.secret_key.len());
    
    println!("\n{}", "⚠️  Security Notice:".bright_yellow());
    println!("  Keep the secret key secure and never share it!");
    
    Ok(())
}

async fn plan_command(report: PathBuf, strategy: String, output: PathBuf) -> Result<()> {
    println!("{} Generating migration plan...", "📋".bright_yellow());
    println!("  Strategy: {}", strategy.bright_white().bold());
    
    // This would integrate with the Python migration planner
    // For now, generate a basic plan structure
    
    let plan_content = format!(r#"# Post-Quantum Cryptography Migration Plan

Generated: {}
Strategy: {}
Source Report: {}

## Overview
This plan outlines the migration from quantum-vulnerable cryptography to post-quantum algorithms.

## Phases

### Phase 1: Assessment & Preparation (Week 1-2)
- Review analysis report
- Set up development environment
- Train team on PQC algorithms
- Establish testing procedures

### Phase 2: Development (Week 3-6)
- Implement hybrid cryptography wrappers
- Develop Kyber-1024 integration
- Develop Dilithium-5 integration
- Create compatibility layer

### Phase 3: Testing (Week 7-8)
- Unit testing of PQC implementations
- Integration testing
- Performance benchmarking
- Security audit

### Phase 4: Staged Rollout (Week 9-12)
- Deploy to 10% of production (canary)
- Monitor for issues
- Gradual rollout to 50%
- Full deployment

### Phase 5: Validation & Cleanup (Week 13-14)
- Verify all systems migrated
- Remove legacy crypto code
- Final security audit
- Documentation update

## Success Criteria
- [ ] All quantum-vulnerable algorithms replaced
- [ ] Zero security incidents during migration
- [ ] Performance within 20% of baseline
- [ ] 100% backwards compatibility maintained

## Rollback Plan
Each phase includes automated rollback capability. In case of critical issues:
1. Trigger automated rollback
2. Notify engineering team
3. Analyze failure logs
4. Address issues before retry
"#, chrono::Local::now().format("%Y-%m-%d %H:%M:%S"), strategy, report.display());
    
    std::fs::write(&output, plan_content)?;
    
    println!("\n{} Migration plan generated: {}", "✓".bright_green(), output.display());
    
    Ok(())
}

async fn test_command(test_type: String) -> Result<()> {
    println!("{} Running PQC tests...\n", "🧪".bright_yellow());
    
    let mut engine = pqc_engine::PQCEngine::new();
    
    let run_kem_test = test_type == "all" || test_type == "kem";
    let run_sig_test = test_type == "all" || test_type == "signature";
    
    if run_kem_test {
        println!("{}", "Testing Kyber-1024 KEM...".bright_blue());
        
        let pb = ProgressBar::new(3);
        pb.set_style(ProgressStyle::default_bar()
            .template("  [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap());
        
        pb.set_message("Generating keypair");
        let keypair = engine.generate_kyber_keypair("test_kem".to_string())?;
        pb.inc(1);
        
        pb.set_message("Encapsulating");
        let (ss1, ct) = engine.kyber_encapsulate(&keypair.public_key)?;
        pb.inc(1);
        
        pb.set_message("Decapsulating");
        let ss2 = engine.kyber_decapsulate(&keypair.secret_key, &ct)?;
        pb.inc(1);
        
        pb.finish_with_message("Complete!");
        
        if ss1 == ss2 {
            println!("  {} Shared secret matched!", "✓".bright_green());
            println!("  Shared secret size: {} bytes", ss1.len());
        } else {
            println!("  {} Test failed!", "✗".bright_red());
        }
        println!();
    }
    
    if run_sig_test {
        println!("{}", "Testing Dilithium-5 Signatures...".bright_blue());
        
        let pb = ProgressBar::new(3);
        pb.set_style(ProgressStyle::default_bar()
            .template("  [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap());
        
        pb.set_message("Generating keypair");
        let keypair = engine.generate_dilithium_keypair("test_sig".to_string())?;
        pb.inc(1);
        
        let message = b"kaliQue_asi PQC test message";
        
        pb.set_message("Signing message");
        let signed_msg = engine.dilithium_sign(&keypair.secret_key, message)?;
        pb.inc(1);
        
        pb.set_message("Verifying signature");
        let verified = engine.dilithium_verify(&keypair.public_key, &signed_msg)?;
        pb.inc(1);
        
        pb.finish_with_message("Complete!");
        
        if verified == message {
            println!("  {} Signature verified!", "✓".bright_green());
            println!("  Signature size: {} bytes", signed_msg.len());
        } else {
            println!("  {} Test failed!", "✗".bright_red());
        }
    }
    
    println!("\n{}", "All tests completed!".bright_green().bold());
    
    Ok(())
}

fn format_report_markdown(report: &crypto_analyzer::AnalysisReport) -> String {
    let mut md = String::from("# Cryptographic Analysis Report\n\n");
    
    md.push_str(&format!("**Files Scanned:** {}\n", report.total_files_scanned));
    md.push_str(&format!("**Crypto Usages Found:** {}\n\n", report.crypto_usages.len()));
    
    md.push_str("## Algorithm Summary\n\n");
    for (algo, count) in &report.algorithm_summary {
        md.push_str(&format!("- **{}**: {} occurrences\n", algo, count));
    }
    
    md.push_str("\n## Risk Summary\n\n");
    for (risk, count) in &report.risk_summary {
        md.push_str(&format!("- **{:?}**: {} occurrences\n", risk, count));
    }
    
    md.push_str("\n## Recommendations\n\n");
    for (i, rec) in report.recommendations.iter().enumerate() {
        md.push_str(&format!("{}. {}\n", i + 1, rec));
    }
    
    md.push_str("\n## Detailed Findings\n\n");
    for usage in &report.crypto_usages {
        md.push_str(&format!("### {} (Line {})\n", usage.file_path, usage.line_number));
        md.push_str(&format!("- **Algorithm:** {}\n", usage.algorithm));
        md.push_str(&format!("- **Risk Level:** {:?}\n", usage.risk_level));
        md.push_str(&format!("- **Code:** `{}`\n\n", usage.code_snippet));
    }
    
    md
}