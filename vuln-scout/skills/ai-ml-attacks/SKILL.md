---
name: AI/ML Attack Surface
description: This skill should be used when the user asks about "AI security", "ML pipeline attacks", "prompt injection", "model deserialization", "unsafe model loading", "Jupyter injection", "LLM security", or needs to identify AI/ML-specific vulnerabilities in codebases that use machine learning frameworks.
version: 1.0.0
---

# AI/ML Attack Surface

## Purpose

Detect security vulnerabilities specific to AI/ML pipelines, LLM-backed applications, and data science workflows. These attack surfaces are increasingly common and often overlooked by traditional SAST tools.

## When to Use

Activate this skill when reviewing code that:
- Imports ML frameworks (torch, tensorflow, sklearn, transformers, langchain)
- Loads serialized models or data
- Integrates LLM APIs (OpenAI, Anthropic, etc.)
- Processes Jupyter notebooks
- Handles training data pipelines

## Vulnerability Categories

### 1. Unsafe Deserialization in ML Pipelines (CWE-502)

The most critical ML-specific vulnerability. Many ML serialization formats execute arbitrary code on load.

**Dangerous Functions:**

| Framework | Dangerous | Safe Alternative |
|-----------|-----------|-----------------|
| PyTorch | `torch.load(path)` | `torch.load(path, weights_only=True)` |
| Joblib | `joblib.load(path)` | Verify source, use `safetensors` |
| NumPy | `numpy.load(path, allow_pickle=True)` | `numpy.load(path, allow_pickle=False)` |
| Scikit-learn | `joblib.load()` / `pickle.load()` | `skops.io` with trusted types |
| TensorFlow | `tf.saved_model.load()` with custom ops | Verify model provenance |
| ONNX | Generally safe | Validate graph structure |
| SafeTensors | Safe by design | Recommended format |

**Detection:**
```bash
# PyTorch unsafe load
grep -rn "torch\.load(" --include="*.py" | grep -v "weights_only=True"

# Joblib/sklearn model loading
grep -rn "joblib\.load\|sklearn.*load" --include="*.py"

# NumPy with pickle enabled
grep -rn "numpy\.load\|np\.load" --include="*.py" | grep "allow_pickle"

# Generic unsafe deserialization in ML context
grep -rn "pickle\.load\|pickle\.loads\|dill\.load\|cloudpickle\.load" --include="*.py"
```

**Exploitation:** An attacker who can supply a malicious model file achieves arbitrary code execution on the server loading the model. This is especially dangerous in:
- Model registries that accept user uploads
- Transfer learning pipelines pulling models from external sources
- CI/CD pipelines that load models during testing

### 2. Prompt Injection (CWE-74)

User input flowing into LLM prompts without sanitization, allowing attackers to override system instructions.

**Patterns to Detect:**

```bash
# Direct string formatting in prompts
grep -rn 'f".*{.*}.*prompt\|f".*{.*}.*system\|\.format(.*user' --include="*.py"

# LangChain prompt templates with user input
grep -rn "PromptTemplate\|ChatPromptTemplate\|HumanMessage" --include="*.py"

# OpenAI/Anthropic API calls with user input in system message
grep -rn "system.*content.*=.*f\"\|system.*content.*\.format" --include="*.py"
grep -rn "messages.*append\|messages.*system" --include="*.py" --include="*.ts" --include="*.js"
```

**Vulnerable Pattern:**
```python
# User input directly in system prompt
prompt = f"You are a helpful assistant. The user's name is {user_input}. Answer their question."
response = openai.chat.completions.create(messages=[{"role": "system", "content": prompt}])
```

**Indicators of Risk:**
- User input concatenated into system messages
- No input validation or sanitization before LLM calls
- LLM output used to make decisions (tool calls, database queries, file operations)

### 3. Jupyter Notebook Injection

Untrusted `.ipynb` files can execute arbitrary code when opened or processed.

**Detection:**
```bash
# Notebook execution in pipelines
grep -rn "nbconvert\|nbclient\|ExecutePreprocessor\|execute_notebook" --include="*.py"

# Papermill execution
grep -rn "papermill\.execute\|pm\.execute" --include="*.py"

# Magic commands in notebooks
grep -rn "%system\|%sx\|!.*pip\|!.*apt\|!.*curl\|!.*wget" --include="*.ipynb"

# IPython display with JS
grep -rn "IPython\.display\.Javascript\|display\.HTML" --include="*.py" --include="*.ipynb"
```

### 4. Untrusted Model Loading

Loading models from untrusted sources (user-specified repos, URLs).

**Detection:**
```bash
# HuggingFace from_pretrained with user-controlled repo
grep -rn "from_pretrained\|AutoModel\|AutoTokenizer\|pipeline(" --include="*.py"

# Verify if the model ID comes from user input
grep -rn "from_pretrained.*request\|from_pretrained.*params\|from_pretrained.*args" --include="*.py"

# TensorFlow Hub
grep -rn "hub\.load\|hub\.KerasLayer" --include="*.py"

# Model download from URLs
grep -rn "urllib.*model\|requests.*model.*download\|wget.*\.pt\|wget.*\.bin" --include="*.py"
```

### 5. Training Data Poisoning Vectors

Paths where an attacker can influence training data.

**Detection:**
```bash
# Writable training data paths
grep -rn "train.*path\|data.*dir\|dataset.*path" --include="*.py" --include="*.yaml" --include="*.yml"

# Unvalidated data pipeline inputs
grep -rn "pd\.read_csv\|pd\.read_json\|pd\.read_sql" --include="*.py" | grep -i "url\|request\|user\|input"

# S3/GCS data loading without integrity checks
grep -rn "s3://\|gs://\|blob\.download" --include="*.py" | grep -v "checksum\|hash\|verify"
```

## Methodology

### Step 1: Identify ML Framework Usage
```bash
grep -rn "import torch\|import tensorflow\|import sklearn\|import transformers\|import langchain\|import openai\|import anthropic" --include="*.py"
```

### Step 2: Find Model Loading Points
```bash
grep -rn "\.load\|from_pretrained\|load_model\|load_weights" --include="*.py"
```

### Step 3: Trace Input Sources
For each loading point, determine if the source (file path, URL, repo ID) can be controlled by an attacker.

### Step 4: Check for Mitigations
- Model signature verification
- Checksum validation
- Allowlisted model sources
- `weights_only=True` for PyTorch
- SafeTensors format usage

## Integration with Other Skills

- Use **dangerous-functions** for the base deserialization sink database
- Use **data-flow-tracing** to trace user input to model loading functions
- Use **secret-scanning** to find API keys for ML services
- Use **cloud-native** for S3/GCS bucket misconfiguration affecting data pipelines
