# Deserialization Attacks Reference

## PHP Object Injection

### Vulnerable Pattern
```php
$data = unserialize($_COOKIE['user_data']);
```

### Exploitation
1. Find classes with magic methods (__destruct, __wakeup, __toString)
2. Chain gadgets to achieve code execution
3. Craft serialized payload

### Common Gadgets
- File write via __destruct
- Command execution via __wakeup
- SQL injection via __toString

### Payload Structure
```
O:8:"ClassName":1:{s:8:"property";s:5:"value";}
```

---

## Java Deserialization

### Vulnerable Pattern
```java
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();
```

### Common Gadget Libraries
- Commons Collections
- Spring Framework
- Apache Commons BeanUtils
- Hibernate

### Tools
- ysoserial: Generate payloads for known gadget chains
- marshalsec: For alternative serialization formats

### Detection
- Magic bytes: `ac ed 00 05` (Java serialization)
- Base64 of above: `rO0AB`

---

## Python Deserialization

### Pickle Exploitation
```python
import pickle
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
```

### YAML Exploitation
```yaml
!!python/object/apply:os.system ['whoami']
```

### Detection
- Look for pickle.loads(), yaml.load()
- Check for user-controlled serialized data

---

## .NET Deserialization

### Vulnerable Formatters
- BinaryFormatter
- ObjectStateFormatter
- NetDataContractSerializer
- SoapFormatter

### Common Gadgets
- TypeConfuseDelegate
- TextFormattingRunProperties
- PSObject

### Tools
- ysoserial.net: Generate .NET gadget payloads

### ViewState Exploitation
- Check for __VIEWSTATE parameter
- Verify if MAC validation is disabled
- Craft malicious ViewState payload

---

## CWE References

| Vulnerability | CWE | Name |
|---------------|-----|------|
| Insecure Deserialization | CWE-502 | Deserialization of Untrusted Data |
| Object Injection | CWE-915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| Type Confusion | CWE-843 | Access of Resource Using Incompatible Type |
