from Kitsune import Kitsune
import numpy as np
import time
from scipy.stats import norm
from matplotlib import pyplot as plt
import pandas as pd
from fpdf import FPDF
import logging
import zipfile

# Örnek yakalamayı aç
print("Örnek Yakalamanın Açılması..")
with zipfile.ZipFile("mirai.zip", "r") as zip_ref:
    zip_ref.extractall()

total_attack_traffic_size = 0
path = "mirai.pcap"  # İşlenecek pcap, pcapng veya tsv dosyası.
packet_limit = np.Inf  # İşlenecek paket sayısı

# KitNET parametreleri
maxAE = 15  # Ensemble katmanındaki her otokodlayıcının maksimum boyutu
FMgrace = 10000  # Özellik eşlemeyi öğrenmek için alınan örneklerin sayısı (ensemble'ın mimarisi)
ADgrace = 75000  # Anomali dedektörünü eğitmek için kullanılan örneklerin sayısı (ensemble kendisi)

# Kitsune oluşturma
K = Kitsune(path, packet_limit, maxAE, FMgrace, ADgrace)

print("Kitsune çalıştırılıyor:")
RMSEs = []
attack_logs = {}
attack_times = []  # Saldırı zamanlarını ve türlerini kaydetmek için liste
i = 0
start = time.time()

# Günlük ayarları
logging.basicConfig(filename='attack_detection.log', level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

while True:
    i += 1
    if i % 1000 == 0:
        print(i)
    rmse = K.proc_next_packet()
    if rmse == -1 or i > 160000:
        break
    if K.detect_attack(rmse) is not None:
        total_attack_traffic_size += len(K.packet)
        attack_time = time.time() - start
        attack_type = K.detect_attack(rmse)[0]
        attack_times.append((attack_time, attack_type))
        logger.info(f"Saldırı tespit edildi {i} pakette, Türü: DDOS, Zaman: {attack_time:.2f} Saniye")
    RMSEs.append(rmse)

stop = time.time()
elapsed_time = stop - start

print("Toplam saldırı trafiği boyutu: ", total_attack_traffic_size)
print("Toplam geçen süre: {:.2f} saniye".format(elapsed_time))

if elapsed_time > 0:
    avg_bytes_per_second = total_attack_traffic_size / elapsed_time
    print("Saniye başına düşen ortalama byte boyutu: {:.2f}".format(avg_bytes_per_second))
else:
    avg_bytes_per_second = 0
    print("Geçen süre, saniye başına ortalama baytı hesaplamak için çok küçük.")

# Saldırı zamanları ve türlerini pandas DataFrame'e dönüştürme
df_attacks = pd.DataFrame(attack_times, columns=["Zaman", "Tür"])

# Saldırı zamanlarının histogramı
plt.figure(figsize=(10, 5))
plt.hist(df_attacks["Zaman"], bins=50)  # 'Time' yerine 'Zaman' kullanıldı
plt.title("Saldırı Zamanlarının Dağılımı")
plt.xlabel("Saniye")
plt.ylabel("Saldırı Sayısı")
plt.savefig('attack_times_histogram.png')
plt.show()

# Anomali tespiti
anomaly_type = K.detect_attack(rmse)  # Saldırı türünü tespit et
if anomaly_type is not None:
    attack_logs[i] = anomaly_type[0]  # Sadece saldırı tespit edilen paketleri kaydet
RMSEs.append(rmse)

print("Tamamlandı. Geçen zaman: " + str(stop - start))

# Saldırı günlüklerini bir dosyaya kaydet
K.save_attack_logs(attack_logs)

# RMSE puanlarını log-normal dağılımına uydurma
benignSample = np.log(RMSEs[FMgrace + ADgrace + 1:160000])
logProbs = norm.logsf(np.log(RMSEs), np.mean(benignSample), np.std(benignSample))

# Anomali Skorları İstatistikleri
avg_anomaly_score = np.mean(RMSEs)
std_dev_anomaly_score = np.std(RMSEs)

# RMSE anomali puanlarını çizme
print("Sonuçları çizme")
plt.figure(figsize=(10, 5))
fig = plt.scatter(range(FMgrace + ADgrace + 1, len(RMSEs)), RMSEs[FMgrace + ADgrace + 1:], s=0.1, c=logProbs[FMgrace + ADgrace + 1:], cmap='RdYlGn')
plt.yscale("log")
plt.title("Kitsune'un Yürütme Aşamasından Anomali Skorları")
plt.ylabel("RMSE (log Ölçekli)")
plt.xlabel("Paket indeksi")
figbar = plt.colorbar()
figbar.ax.set_ylabel('Log Olasılığı\n ', rotation=270)
plt.savefig('rmse_anomaly_scores.png')
plt.show()

pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", size=12)

pdf.cell(200, 10, txt="Kitsune Attack Detection Report", ln=True, align='C')
pdf.cell(200, 10, txt=f"Total attack traffic size: {total_attack_traffic_size} bytes", ln=True)
pdf.cell(200, 10, txt=f"Elapsed time: {elapsed_time:.2f} seconds", ln=True)
pdf.cell(200, 10, txt=f"Average bytes per second: {avg_bytes_per_second:.2f}", ln=True)

pdf.cell(200, 10, txt="Attack Times Histogram:", ln=True)
pdf.image('attack_times_histogram.png', x=10, y=None, w=190)
pdf.cell(200, 10, txt="RMSE Anomaly Scores:", ln=True)
pdf.image('rmse_anomaly_scores.png', x=10, y=None, w=190)

# Anomali Skorları İstatistikleri
pdf.cell(200, 10, txt="Anomaly Scores Statistics:", ln=True)
pdf.cell(200, 10, txt=f"Average Anomaly Score: {avg_anomaly_score:.2f}", ln=True)
pdf.cell(200, 10, txt=f"Standard Deviation of Anomaly Score: {std_dev_anomaly_score:.2f}", ln=True)

pdf.output("Kitsune_Attack_Detection_Report.pdf")

print("PDF raporu oluşturuldu: Kitsune_Attack_Detection_Report.pdf")