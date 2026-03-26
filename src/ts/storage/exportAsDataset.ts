import { getDatabase } from "./database.svelte";
import { downloadFile } from "../globalApi.svelte";
import { alertNormal, alertError } from "../alert";
import { language } from "src/lang";

// Threshold to guard against absurdly large or corrupted message arrays.
const MAX_MESSAGES_PER_CHAT = 100_000;

type DatasetMessage = {
    role: "user" | "char";
    data: string;
    saying?: string;
    time?: number;
    name?: string;
};

type DatasetRow = {
    name: string;
    description: string;
    chats: DatasetMessage[];
    lorebook: unknown[];
};

function safeString(value: unknown): string {
    return typeof value === "string" ? value : "";
}

function safeNumber(value: unknown): number | undefined {
    return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function safeArray<T>(value: unknown): T[] {
    return Array.isArray(value) ? (value as T[]) : [];
}

function normalizeMessage(msg: unknown): DatasetMessage | null {
    if (!msg || typeof msg !== "object") return null;
    const m = msg as Record<string, unknown>;
    const role = m.role === "char" ? "char" : "user";
    const data = safeString(m.data);
    const saying = typeof m.saying === "string" ? m.saying : undefined;
    const time = safeNumber(m.time);
    const name = typeof m.name === "string" ? m.name : undefined;
    return { role, data, saying, time, name };
}

function normalizeLorebook(value: unknown): unknown[] {
    const arr = safeArray<unknown>(value);
    const result: unknown[] = [];
    for (const item of arr) {
        try {
            result.push(JSON.parse(JSON.stringify(item ?? null)));
        } catch {
            result.push({ corrupted: true });
        }
    }
    return result;
}

function normalizeMessages(value: unknown): DatasetMessage[] {
    const arr = safeArray<unknown>(value);
    if (arr.length > MAX_MESSAGES_PER_CHAT) {
        throw new Error(`message array too large: ${arr.length}`);
    }
    const result: DatasetMessage[] = [];
    for (const msg of arr) {
        const normalized = normalizeMessage(msg);
        if (normalized) {
            result.push(normalized);
        }
    }
    return result;
}

export async function exportAsDataset() {
    const db = getDatabase();

    const dataset: DatasetRow[] = [];
    const skipped: string[] = [];

    for (const char of safeArray<Record<string, unknown>>(db.characters)) {
        if (!char || typeof char !== "object") {
            skipped.push("[unknown character]: invalid character object");
            continue;
        }

        if (char.type === "group") {
            continue;
        }

        const charName = safeString(char.name) || "[unnamed character]";
        const charDesc = safeString(char.desc);
        const lorebook = normalizeLorebook(char.globalLore);

        if (!Array.isArray(char.chats)) {
            skipped.push(`${charName}: chats is not an array`);
            continue;
        }

        const chats = char.chats as unknown[];
        for (let i = 0; i < chats.length; i++) {
            const chat = chats[i] as Record<string, unknown> | null | undefined;
            try {
                if (!chat || typeof chat !== "object") {
                    throw new Error("chat is not an object");
                }
                const normalizedMessages = normalizeMessages(chat.message);
                dataset.push({
                    name: charName,
                    description: charDesc,
                    chats: normalizedMessages,
                    lorebook
                });
            } catch (err) {
                const errMsg = err instanceof Error ? err.message : String(err);
                const chatName = typeof chat?.name === "string" ? chat.name : `chat#${i}`;
                skipped.push(`${charName} / ${chatName}: ${errMsg}`);
                console.error("[exportAsDataset] skipped broken chat", {
                    charName,
                    chatIndex: i,
                    error: err
                });
            }
        }
    }

    try {
        const json = JSON.stringify(dataset, null, 4);
        await downloadFile("dataset.json", Buffer.from(json, "utf-8"));
    } catch (err) {
        console.error("[exportAsDataset] final stringify/download failed", err);
        alertError(`Dataset export failed: ${err instanceof Error ? err.message : String(err)}`);
        return;
    }

    if (skipped.length > 0) {
        console.warn("[exportAsDataset] skipped entries", skipped);
        const report = [
            `Exported dataset rows: ${dataset.length}`,
            `Skipped chats: ${skipped.length}`,
            "",
            ...skipped
        ].join("\n");
        try {
            await downloadFile("dataset-export-skipped.txt", Buffer.from(report, "utf-8"));
        } catch {
            // Non-fatal: the main export already succeeded.
            console.warn("[exportAsDataset] could not write skipped report");
        }
        alertNormal(language.successExportPartial);
        return;
    }

    alertNormal(language.successExport);
}