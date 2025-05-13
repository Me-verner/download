import os
from huggingface_hub import snapshot_download, HfApi
from tqdm import tqdm

# مسیر کش
BASE_CACHE_DIR = r"./cache"
os.makedirs(BASE_CACHE_DIR, exist_ok=True)

# دریافت توکن
HF_TOKEN = input("🔑 Enter your Hugging Face token: ").strip()

# استفاده از IPv6
ip_version = input("🌐 Which IP version should be used? (6 for IPv6, else default): ").strip()
if ip_version == "6":
    os.environ["HF_HUB_ENABLE_IPV6"] = "1"
    os.environ["CURL_CA_BUNDLE"] = ""
    print("✅ IPv6 mode enabled.\n")
else:
    print("ℹ️ Using default IP stack.\n")

# تست توکن
api = HfApi()
try:
    user = api.whoami(token=HF_TOKEN)
    print(f"🔐 Logged in as: {user['name']}\n")
except Exception as e:
    print(f"❌ Invalid token: {e}")
    exit(1)

# لیست مدل‌ها
MODELS = [
    "HiDream-ai/HiDream-I1-Full",
    "HiDream-ai/HiDream-I1-Dev",
    "HiDream-ai/HiDream-I1-Fast",
    "azaneko/HiDream-I1-Full-nf4",
    "azaneko/HiDream-I1-Dev-nf4",
    "azaneko/HiDream-I1-Fast-nf4",
    "meta-llama/Llama-3.1-8B-Instruct"
]

# چاپ جدول مدل‌ها
print("🧠 Available Models:\n")
for i, model in enumerate(MODELS, 1):
    print(f"  {i}. {model}")
print("\nType one of the following:")
print("  - A single number (e.g. 3)")
print("  - A list of numbers separated by commas (e.g. 1,3,5)")
print("  - 'all' to download all models")

selection = input("\n📥 Select model(s) to download: ").strip().lower()

# انتخاب مدل‌ها
if selection == "all":
    selected_models = MODELS
else:
    try:
        indices = [int(i.strip()) - 1 for i in selection.split(",")]
        selected_models = [MODELS[i] for i in indices if 0 <= i < len(MODELS)]
    except Exception:
        print("❌ Invalid selection.")
        exit(1)

print(f"\n📦 Downloading {len(selected_models)} model(s) into: {BASE_CACHE_DIR}\n")

# دانلود
for model_id in selected_models:
    model_folder = model_id.replace("/", "--")
    output_path = os.path.join(BASE_CACHE_DIR, model_folder)

    print(f"🔽 Downloading {model_id} → {output_path}")
    try:
        snapshot_download(
            repo_id=model_id,
            local_dir=output_path,
            token=HF_TOKEN,
            local_dir_use_symlinks=False,
            ignore_patterns=["*.msgpack"],
            tqdm_class=tqdm
        )
        print(f"✅ Finished: {model_id}\n")
    except Exception as e:
        print(f"❌ Failed to download {model_id}: {e}\n")

print("🎉 All selected models downloaded.")
