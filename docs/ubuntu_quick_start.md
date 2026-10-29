---
title: "NHP Quick Start Ubuntu"
layout: page
nav_order: 2
parent: Getting Started
description: "Set up OpenNHP on Ubuntu and verify access to a protected service."
permalink: /ubuntu_quick_start/
---

# Ubuntu Quick Start

This guide walks through setting up OpenNHP on Ubuntu and
verifying access to a protected service.

## Before you begin

Document the following once the procedure has been tested:

- Supported Ubuntu version
- Required hardware and network access
- Whether this guide uses Docker or native binaries
- Required administrator privileges

## Architecture

Explain where the NHP-Agent, NHP-Server, access controller,
and protected application run.

## 1. Install prerequisites

Add the tested installation commands here.

## 2. Configure OpenNHP

Explain the configuration files and values the reader must change.

## 3. Start the services

Add startup commands and expected output.

## 4. Verify access

Verify that:

1. Access is blocked before authorization.
2. An authorized client can knock successfully.
3. The protected service becomes reachable.
4. New access is blocked after the authorization expires.

## Troubleshooting

Describe common errors and how to diagnose them.

## Stop and clean up

Explain how to stop the services and undo the changes.



-----

# Proposed Documentation Structure

Pages marked **Planned** are suggestions for future contributions.
Sections should appear in the navigation only when they contain published content.

## Overview

- OpenNHP Overview
- Features
- Comparison: NHP and SPA
- Glossary

## Getting Started

- Choose Your Installation Path — **Planned**
- NHP Quick Start — Docker
- NHP Quick Start — Ubuntu — **Draft**
- DHP Quick Start

## Deployment

- Deploy OpenNHP Binaries
- Single-Host Deployment — **Planned**
- Separate Server and Access Controller — **Planned**
- Multi-Instance Server Clusters

## Integration Guides — Planned

- Protect an Existing HTTPS API
- Connect an Existing Identity Provider
- Browser Application Access
- Mobile Application Access
- Server-to-Server Access

## Migration Guides — Planned

- Plan an NHP Migration
- Introduce NHP Alongside Existing Access
- Cut Over, Verify, and Roll Back

## Operations — Planned

- Troubleshooting
- Logging and Monitoring
- Key Rotation and Agent Revocation
- Upgrading OpenNHP

## Development

- Build from Source
- Understand the Source Code
- Client SDKs
- Server Plugin Development
- Capture Diagram Animations
- Contribute Documentation — **Planned**

## Technical Reference

- Cryptography
- Protocol Reference
  - Message Header
  - Message Types
- Configuration Reference — **Planned**

## Contributor Placement Guidelines

| Content purpose | Section |
| --- | --- |
| Explain OpenNHP and its capabilities | Overview |
| Reach a first working deployment | Getting Started |
| Install a particular environment or topology | Deployment |
| Connect existing applications or identity systems | Integration Guides |
| Transition an existing system to NHP | Migration Guides |
| Maintain, diagnose, or recover a deployment | Operations |
| Build or extend OpenNHP | Development |
| Document exact settings, interfaces, or messages | Technical Reference |

## Guide Requirements

Each implementation guide should include:

- Audience and intended outcome
- Tested OpenNHP version and environment
- Prerequisites
- Component topology and public entry points
- Instructions with expected results
- Verification steps
- Troubleshooting
- Cleanup or rollback instructions

## Organization Principles

- Preserve existing page URLs when reorganizing navigation.
- Link to existing instructions rather than duplicating them.
- Add new sections when their first reviewed page is ready.
- Keep design proposals clearly distinguished from tested user guides.