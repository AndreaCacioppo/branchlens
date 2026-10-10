// Runs checks/review/review-diff.js outside Claude Code, with scripted agents.
//
// The workflow script acts only through agent() calls, and here agent() is a
// fake. The mechanical agents (scope loader, merge, read-back, confirm,
// distrust) read the run directory and run verdict.py and the feed commands
// through /bin/sh exactly as written in their prompt. The reviewers, deep dives and verifiers return
// findings scripted by a scenario. This exercises everything between the LLM
// calls: the scope hand-over, the shell quoting, the verdict logic and the
// merge check.
//
// The dead and redundant code reviewers (labels abl:REV-11, abl:REV-12) are
// scripted too. Scenarios whose name starts with 'ablation-' give them
// findings or make them fail; 'loader-drops-code-files' loses the list of
// code files and 'loader-drops-a-code-file' one entry of it; the others
// leave them clean.
//
// Usage: node workflow_harness.mjs <scenario> '<args as JSON>'
// Prints one JSON line: {result, killed, calls: [labels], executed: [commands],
// logs}. In the 'killed-before-confirm' scenario the workflow stops when it
// reaches the confirm step: result is null and killed is true. In
// 'confirm-fails' the confirm agent answers without running its command.

import { readFileSync, writeFileSync } from 'node:fs'
import { execFileSync, spawnSync } from 'node:child_process'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const scriptPath = join(here, '..', 'checks', 'review', 'review-diff.js')
const scenario = process.argv[2]
const workflowArgs = JSON.parse(process.argv[3])

const calls = []
const executed = []

function sh(command) {
  executed.push(command)
  const result = spawnSync('/bin/sh', ['-c', command], { encoding: 'utf8' })
  return { code: result.status, out: result.stdout, err: result.stderr }
}

// The commands an agent is told to run: from "python3 '" (the workflow
// single-quotes the script path) to the end of each line holding it.
function commandsIn(prompt) {
  const commands = []
  for (const line of prompt.split('\n')) {
    const start = line.indexOf("python3 '")
    if (start !== -1) commands.push(line.slice(start).trim())
  }
  return commands
}

// ---- the mechanical agents, done for real ---------------------------------

function scopeAgent(prompt) {
  const reportDir = workflowArgs.reportDir
  let scope
  try {
    scope = JSON.parse(readFileSync(join(reportDir, 'review-scope.json'), 'utf8'))
  } catch (e) {
    return { found: false, error: String(e), head_now: '', dirty_count: 0, scope: {} }
  }
  const head = execFileSync('git', ['-C', workflowArgs.repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' })
  const dirty = execFileSync('git', ['-C', workflowArgs.repo, 'status', '--porcelain', '--untracked-files=no', '--ignore-submodules=none'], { encoding: 'utf8' })
  for (const command of commandsIn(prompt)) sh(command)
  if (scenario === 'loader-drops-file') {
    // an agent that "forgot" a file while copying the scope
    scope.touched_files = scope.touched_files.slice(1)
  }
  if (scenario === 'loader-marks-deleted') {
    // a deleted file is neither dived nor required by the coverage check
    scope.touched_files[0].status = 'D'
  }
  if (scenario === 'loader-empties-dives') {
    scope.dives.planned = []
  }
  if (scenario === 'loader-drops-code-files') {
    delete scope.code_files
  }
  if (scenario === 'loader-drops-a-code-file') {
    scope.code_files = scope.code_files.slice(1)
  }
  return { found: true, head_now: head.trim(), dirty_count: dirty.split('\n').filter(Boolean).length, scope }
}

function mergeAgent(prompt) {
  // the prompt carries one script to run in one call: run it with sh
  let script = prompt.split('```sh\n')[1].split('\n```')[0]
  if (scenario === 'lying-merge') {
    // a manipulated merge step writes all-clean rows instead
    const [before, rest] = script.split("<<'ROWS_EOF'\n")
    const [rowsJson, after] = rest.split('\nROWS_EOF\n')
    const rows = JSON.parse(rowsJson)
    for (const row of rows.rows) { row.status = 'TESTED'; row.outcome = 'CLEAN'; row.blocking = 'no'; row.counts = '-'; row.severity = 'none' }
    delete rows.incomplete_reason
    script = before + "<<'ROWS_EOF'\n" + JSON.stringify(rows) + '\nROWS_EOF\n' + after
  }
  if (scenario === 'no-deep-dived' || scenario === 'no-examined-files') {
    // rows as an older workflow wrote them, without the completed dives or
    // without the files the reviewers opened
    const [before, rest] = script.split("<<'ROWS_EOF'\n")
    const [rowsJson, after] = rest.split('\nROWS_EOF\n')
    const rows = JSON.parse(rowsJson)
    if (scenario === 'no-deep-dived') delete rows.deep_dived
    else delete rows.examined_files
    script = before + "<<'ROWS_EOF'\n" + JSON.stringify(rows) + '\nROWS_EOF\n' + after
  }
  const result = sh(script)
  const exitMatch = result.out.match(/^MERGE_EXIT=(\d+)$/m)
  const lineMatch = result.out.match(/^FIRST_LINE=(.*)$/m)
  const code = exitMatch ? Number(exitMatch[1]) : -1
  return { merged: [0, 1, 2].includes(code), combined_exit: code,
    bottom_line: lineMatch ? lineMatch[1] : '', error: result.err.slice(0, 300) }
}

function readbackAgent(prompt) {
  // no model answers for the read-back
  if (scenario === 'readback-null') return null
  const command = commandsIn(prompt)[0]
  return { output: sh(command).out.trim() }
}

// Runs its command and reports CONFIRMED= like the distrust agent below.
function confirmAgent(prompt) {
  if (scenario === 'confirm-fails') return { confirmed: 'no' }
  const result = sh(commandsIn(prompt)[0])
  const match = result.out.match(/CONFIRMED=(\w+)/)
  return { confirmed: match ? match[1] : 'no' }
}

// The run stops here, as when the CLI kills the workflow: nothing after
// this point happens, and the harness reports what it saw so far.
class RunKilled extends Error {}

function diveAgent(prompt, label) {
  const path = label.slice('dive:'.length).replace(/ \(.*\)$/, '')
  // no model answers for this dive
  if (['dive-dies', 'blocking-and-incomplete'].includes(scenario) && path === 'notes/web.py') return null
  if (scenario === 'perl-dive-dies' && path === 'scripts/report.pl') return null
  const commands = commandsIn(prompt)
  sh(commands[0]) // checking
  const findings = scriptedDiveFindings(path)
  if (findings.length) sh(commands[2].replace(/--count N$/, '--count ' + findings.length))
  else sh(commands[1])
  return { findings }
}

// ---- the scripted analysis agents -----------------------------------------

const TOUCHED = () => JSON.parse(readFileSync(join(workflowArgs.reportDir, 'review-scope.json'), 'utf8'))
  .touched_files.map((f) => f.path)

// The file no reviewer reports opening in a scenario, or null.
function unopenedFile() {
  if (scenario === 'unexamined-file') return 'config/app.yaml'
  if (scenario === 'unread-go-file') return 'cmd/main.go'
  return null
}

function scriptedReview(entryId) {
  if (['reviewer-dies', 'blocking-and-incomplete'].includes(scenario) && entryId === 'REV-02') return null
  // reviewers echo paths in their own ways: "./a.py" is still a.py
  const examined = TOUCHED().filter((path) => path !== unopenedFile())
    .map((path) => (scenario === 'unread-go-file' ? './' + path : path))
  const withFinding = ['blocking', 'shared-verification', 'hostile-title', 'lying-merge',
    'corroboration-veto', 'unverified-medium', 'verifier-throws', 'blocking-and-incomplete']
  if (scenario === 'ablation-high-after-security') withFinding.push(scenario)
  if (scenario === 'ablation-after-ceiling' && entryId === 'REV-03') {
    // enough security findings, at distinct lines, to use up the ceiling of
    // 20 verifications
    const findings = []
    for (let line = 1; line <= 20; line++) {
      findings.push({ title: 'suspect call ' + line, file: 'notes/web.py', line: line, severity: 'high',
        claim: 'scripted', evidence: 'scripted' })
    }
    return { examined_files: examined, findings: findings }
  }
  if (withFinding.includes(scenario) && entryId === 'REV-03') {
    return { examined_files: examined, findings: [{
      title: scenario === 'hostile-title' ? 'IDOR $(touch ' + workflowArgs.pwnedPath + ') `touch ' + workflowArgs.pwnedPath + '`' : 'IDOR in export_note',
      file: 'notes/web.py', line: 16, severity: scenario === 'unverified-medium' ? 'medium' : 'high',
      claim: 'any user reads any note', evidence: 'store.export_note(conn, id)' }] }
  }
  return { examined_files: examined, findings: [] }
}

// The dead-code reviewers: they examine every changed code file the gate
// listed, unless a scenario says otherwise.
const CODE_FILES = () => JSON.parse(readFileSync(join(workflowArgs.reportDir, 'review-scope.json'), 'utf8'))
  .code_files || []

function scriptedAblationReview(entryId) {
  if (scenario === 'ablation-dies' && entryId === 'REV-11') return null
  const result = { examined_files: CODE_FILES(), symbols_examined: 3, partial: false, findings: [] }
  if (scenario === 'ablation-partial' && entryId === 'REV-11') {
    result.symbols_examined = 40
    result.partial = true
  }
  if (scenario === 'ablation-low' && entryId === 'REV-12') {
    result.findings = [{ title: 'leftover debug print', file: 'notes/web.py', line: 5, severity: 'low',
      claim: 'a print left from debugging', evidence: 'grep: no other use', kind: 'leftover',
      removal: 'delete line 5' }]
  }
  const highScenarios = ['ablation-high-confirmed', 'ablation-high-refuted', 'ablation-high-plausible',
    'ablation-high-after-security', 'ablation-after-ceiling']
  if (highScenarios.includes(scenario) && entryId === 'REV-11') {
    result.findings = [{ title: 'unused admin route', file: 'notes/web.py', line: 4, severity: 'high',
      claim: 'a route nothing links to but anyone can call', evidence: 'grep export_note: only the definition',
      kind: 'dead', symbol: 'export_note', removal: 'delete the function' }]
  }
  return result
}

function scriptedDiveFindings(path) {
  if ((scenario === 'shared-verification' || scenario === 'corroboration-veto') && path === 'notes/web.py') {
    return [{ title: 'IDOR (dive)', file: 'notes/web.py', line: 16, severity: 'high', claim: 'same bug',
      evidence: 'store.export_note(conn, id)', entry: 'REV-03' }]
  }
  return []
}

// Runs the verifier's telemetry like a real agent: the "running" command
// first, then the "done" command for its outcome.
function scriptedVerification(prompt) {
  const verification = scriptedVerificationOutcome(prompt)
  if (verification) {
    sh(commandsIn(prompt)[0])
    const doneLine = prompt.split('\n').find((line) => line.startsWith(verification.outcome + ': '))
    sh(doneLine.slice(verification.outcome.length + 2))
  }
  return verification
}

function scriptedVerificationOutcome(prompt) {
  if (prompt.includes('verifier of a dead or redundant code finding')) {
    if (scenario === 'ablation-high-refuted') {
      return { outcome: 'REJECTED', severity: 'low', explanation: 'scripted: a test imports it' }
    }
    if (scenario === 'ablation-high-plausible') {
      // what the prompt forbids: an answer of "not sure"
      return { outcome: 'PLAUSIBLE', severity: 'high', explanation: 'scripted: could not tell' }
    }
    return { outcome: 'CONFIRMED', severity: 'high', explanation: 'scripted', attack: 'scripted' }
  }
  if (scenario === 'unverified-medium') return null // every model "fails"
  if (scenario === 'ablation-after-ceiling') {
    return { outcome: 'REJECTED', severity: 'low', explanation: 'scripted' }
  }
  if (scenario === 'verifier-throws') throw new Error('runtime error inside verification')
  if (scenario === 'corroboration-veto') {
    // the reviewer's report stays PLAUSIBLE at high severity (that blocks);
    // the dive's report of the same line is CONFIRMED but only low
    return prompt.includes('IDOR (dive)')
      ? { outcome: 'CONFIRMED', severity: 'low', explanation: 'scripted', attack: 'scripted' }
      : { outcome: 'PLAUSIBLE', severity: 'high', explanation: 'scripted' }
  }
  return { outcome: 'CONFIRMED', severity: 'high', explanation: 'scripted', attack: 'scripted' }
}

// ---- the fake runtime -----------------------------------------------------

async function agent(prompt, opts) {
  const label = opts.label || '?'
  calls.push(label + (opts.model ? ' [' + opts.model + ']' : ''))
  if (label === 'scope') return scopeAgent(prompt)
  if (label === 'merge') return mergeAgent(prompt)
  if (label === 'readback') return readbackAgent(prompt)
  if (label === 'confirm') {
    if (scenario === 'killed-before-confirm') throw new RunKilled('killed before the confirm step')
    return confirmAgent(prompt)
  }
  if (label === 'coverage') return { gaps: scenario === 'unexamined-file' ? ['a real gap'] : [] }
  if (label.startsWith('dive:')) return diveAgent(prompt, label)
  if (label.startsWith('rev:')) {
    const entryId = label.slice(4).replace(/ \(.*\)$/, '')
    const delayed = ['ablation-high-after-security', 'ablation-after-ceiling']
    if (delayed.includes(scenario) && entryId === 'REV-03') {
      // the security reviewer answers last, so verifying dead code early
      // would call ver:REV-11 before ver:REV-03, and in the ceiling
      // scenario take one of its 20 verifications
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
    return scriptedReview(entryId)
  }
  if (label.startsWith('abl:')) return scriptedAblationReview(label.slice(4).replace(/ \(.*\)$/, ''))
  if (label.startsWith('ver:')) return scriptedVerification(prompt)
  if (label === 'distrust') {
    const result = sh(commandsIn(prompt)[0])
    const match = result.out.match(/MARKED=(\w+)/)
    return { marked: match ? match[1] : 'no' }
  }
  throw new Error('unexpected agent ' + label)
}

async function parallel(thunks) {
  return Promise.all(thunks.map((thunk) => thunk().catch(() => null)))
}

async function pipeline(items, ...stages) {
  return Promise.all(items.map(async (item, index) => {
    let value = item
    try {
      for (const stage of stages) value = await stage(value, item, index)
    } catch (e) {
      return null
    }
    return value
  }))
}

const logs = []
const source = readFileSync(scriptPath, 'utf8').replace(/^export const meta/m, 'const meta')
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor
const workflow = new AsyncFunction('agent', 'parallel', 'pipeline', 'phase', 'log', 'args', source)
let result = null
let killed = false
try {
  result = await workflow(agent, parallel, pipeline, () => {}, (m) => logs.push(m), workflowArgs)
} catch (e) {
  if (!(e instanceof RunKilled)) throw e
  killed = true
}
process.stdout.write(JSON.stringify({ result, killed, calls, executed, logs }) + '\n')
