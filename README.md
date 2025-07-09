# 🔍 IntrospectorX

<p align="center">
  <img src="https://github.com/nkbeast/IntrospectorX/blob/main/banner.png" width="700px" alt="IntrospectorX Logo">
</p>

<p align="center">
  <a href="https://github.com/nkbeast/IntrospectorX"><img src="https://img.shields.io/github/stars/nkbeast/IntrospectorX?style=for-the-badge&color=black" alt="Stars"></a>
  <a href="https://github.com/nkbeast/IntrospectorX"><img src="https://img.shields.io/github/forks/nkbeast/IntrospectorX?style=for-the-badge&color=black" alt="Forks"></a>
  <a href="#"><img src="https://img.shields.io/badge/GraphQL-Scanner-red?style=for-the-badge&logo=graphql" alt="GraphQL"></a>
  <a href="#"><img src="https://img.shields.io/badge/Made%20for-Bugbounty-blue?style=for-the-badge&logo=bugcrowd" alt="Bug Bounty"></a>
</p>

<br>

> 🚀 **IntrospectorX** is a blazing-fast **GraphQL introspection vulnerability scanner** built for bug bounty hunters, penetration testers, and API security researchers. It mimics real-world introspection queries used by Apollo, GraphiQL, Insomnia, and Postman to uncover exposed GraphQL schemas.

---

## 🧠 Why IntrospectorX?

- ✅ Detects misconfigured GraphQL endpoints using common introspection payloads
- ⚡ Multi-threaded scanning with performance optimization
- 📝 Generates clean HTML vulnerability reports
- 💬 Verbose mode for audit & CLI visibility
- 🕵️‍♂️ Designed for automation, recon pipelines, and CI/CD environments

---

## 🚀 Installation

```bash
git clone https://github.com/nkbeast/IntrospectorX
cd IntrospectorX
pip3 install -r requirements.txt
python3 introspectorx.py --help
