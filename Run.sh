#!/bin/bash
screen -S ChatBackend -X quit
screen -dmS ChatBackend node Chat-Backend.js