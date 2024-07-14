from FeatureExtractor import FE
from KitNET.KitNET import KitNET

class Kitsune:
    def __init__(self, file_path, limit, max_autoencoder_size=15, FM_grace_period=10000, AD_grace_period=75000,
                 learning_rate=0.05, hidden_ratio=0.8, threshold=0.4):
        self.FE = FE(file_path, limit)
        self.total_attack_traffic_size = 0
        self.AnomDetector = KitNET(self.FE.get_num_features(), max_autoencoder_size, FM_grace_period, AD_grace_period,
                                   learning_rate, hidden_ratio)
        self.threshold = threshold
        self.packet = None  # packet adında bir öznitelik ekleyin ve başlangıçta None olarak ayarlayın

    def proc_next_packet(self):
        x = self.FE.get_next_vector()
        if len(x) == 0:
            return -1

        rmse = self.AnomDetector.process(x)
        self.packet = x  # Her işlendikten sonra packet özniteliğini güncelleyin

        if self.detect_attack(rmse) is not None:
            self.total_attack_traffic_size += len(x)

        return rmse

    def detect_attack(self, rmse):
        if rmse > self.threshold:
            return "Saldırı Tespit Edildi"
        else:
            return None

    def save_attack_logs(self, attack_logs):
        with open("saldiri_kaydi.txt", "w") as f:
            for packet_index, attack_type in attack_logs.items():
                if attack_type is not None:
                    f.write(f"paket {packet_index}: {attack_type}\n")
