"""Digital Chakravyuha - layered security simulation."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import random
import time
from typing import Callable, Iterable, List


@dataclass
class LayerResult:
    signal: str
    log: List[str] = field(default_factory=list)
    token: str | None = None


Layer = Callable[[LayerResult], LayerResult]


def mirage_gate(layer_result: LayerResult) -> LayerResult:
    illusion = layer_result.signal[::-1] + str(random.randint(100, 999))
    layer_result.log.append("MirageGate: Illusion protocol engaged.")
    layer_result.signal = illusion
    return layer_result


def sudarshan(layer_result: LayerResult) -> LayerResult:
    purified = "".join(filter(str.isalnum, layer_result.signal))
    layer_result.log.append("Sudarshan: Corruption sliced.")
    layer_result.signal = purified
    return layer_result


def kavach(layer_result: LayerResult) -> LayerResult:
    protected = hashlib.sha256(layer_result.signal.encode()).hexdigest()
    layer_result.log.append("Kavach: Dynamic shield activated.")
    layer_result.signal = protected
    return layer_result


def kundal_subnet(layer_result: LayerResult) -> LayerResult:
    spark = f"Kundal::{layer_result.signal}::Spark{random.randint(1000, 9999)}"
    layer_result.log.append("Kundal: Creative sparks detected.")
    layer_result.signal = spark
    return layer_result


def akashic(layer_result: LayerResult) -> LayerResult:
    encoded = hashlib.md5(layer_result.signal.encode()).hexdigest()
    layer_result.log.append("Akashic: Universal memory accessed.")
    layer_result.signal = f"AkashicNet[{encoded}]"
    return layer_result


def karma_mirror(layer_result: LayerResult) -> LayerResult:
    mirror = layer_result.signal + layer_result.signal[::-1]
    layer_result.log.append("KarmaMirror: Reflection executed.")
    layer_result.signal = mirror
    return layer_result


def om(layer_result: LayerResult) -> LayerResult:
    layer_result.log.append("Om: Universal resonance initiated.")
    layer_result.signal = f"OM::{layer_result.signal}::OM"
    return layer_result


def vasudev_protocol(layer_result: LayerResult) -> LayerResult:
    scrambled = "".join(random.sample(layer_result.signal, len(layer_result.signal)))
    layer_result.log.append("Vasudev: Time-distortion shield enabled.")
    layer_result.signal = scrambled
    return layer_result


def kalki_coin(layer_result: LayerResult) -> LayerResult:
    coin = hashlib.sha1(layer_result.signal.encode()).hexdigest()
    layer_result.log.append("KalkiCoin: Karma hash validated.")
    layer_result.token = f"KalkiCoin<{coin}>"
    return layer_result


class DigitalChakravyuha:
    """Run signals through the seven-layer digital fortress."""

    def __init__(self, layers: Iterable[Layer] | None = None, delay_s: float = 0.2) -> None:
        self.layers = list(
            layers
            or [
                mirage_gate,
                sudarshan,
                kavach,
                kundal_subnet,
                akashic,
                karma_mirror,
                om,
                vasudev_protocol,
                kalki_coin,
            ]
        )
        self.delay_s = delay_s

    def execute(self, input_signal: str) -> LayerResult:
        result = LayerResult(signal=input_signal)
        for layer in self.layers:
            result = layer(result)
            if self.delay_s:
                time.sleep(self.delay_s)
        return result


def run_demo() -> None:
    chakravyuha = DigitalChakravyuha()
    result = chakravyuha.execute("AbhimanyuProtocolStart2025")

    print("\n🚀 FINAL SIGNAL:", result.signal)
    print("🪙 KALKI COIN:", result.token)
    print("\n📜 EXECUTION LOG:")
    for log in result.log:
        print(" -", log)


if __name__ == "__main__":
    run_demo()
