# Digital Chakravyuha

Digital Chakravyuha is a mythic-inspired, layered security simulation. Each layer transforms an input signal to model how a fortress of defenses can obscure, harden, and validate access as it moves inward toward the core.

## Conceptual Layers

1. **Mirage Gate** – obfuscation and misdirection.
2. **Sudarshan** – purification and slicing of corrupted input.
3. **Kavach** – strong cryptographic shield.
4. **Kundal Subnet** – creative spark injection.
5. **Akashic** – knowledge compression and encoding.
6. **Karma Mirror** – reflection and self-validation.
7. **Om** – resonance alignment.
8. **Vasudev Protocol** – final scrambling before sealing.
9. **Kalki Coin** – tokenized integrity proof.

## Run the demo

```bash
python digital_chakravyuha.py
```

The script prints the final signal, a proof token, and a log of each layer's action.

## Custom usage

You can build your own layer pipeline by passing callables into `DigitalChakravyuha`:

```python
from digital_chakravyuha import DigitalChakravyuha, mirage_gate, sudarshan

chakravyuha = DigitalChakravyuha(layers=[mirage_gate, sudarshan], delay_s=0)
result = chakravyuha.execute("AbhimanyuProtocolStart2025")
print(result.signal)
```
