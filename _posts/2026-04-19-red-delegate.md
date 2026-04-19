---
title: "VL: Delegate"
date: 2026-04-19 12:00:00 +0000
categories: [WriteUp, Vulnlab]
tags: [Windows, Active Directory, Medium]
image:
  path: https://www.vulnlab.com/img/machines/delegate.png
  alt: Delegate Machine Logo
---

## Introducción
Esta es una máquina de **Vulnlab** enfocada en enumeración de Active Directory.

## Enumeración
Empezamos con un escaneo de nmap:
```bash
nmap -sC -sV -p- 10.10.11.x
```
