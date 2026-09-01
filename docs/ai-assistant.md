---
layout: default
title: GPShell3 AI Assistant
permalink: /ai-assistant/
---

<style>
  .ai-assistant {
    max-width: 980px;
    color: #17212b;
  }
  .ai-assistant * {
    box-sizing: border-box;
  }
  .ai-assistant__intro {
    display: grid;
    grid-template-columns: auto minmax(0, 1fr);
    gap: 16px;
    align-items: start;
    margin: 0 0 24px;
  }
  .ai-assistant__mark {
    width: 44px;
    height: 44px;
    object-fit: contain;
  }
  .ai-assistant h1,
  .ai-assistant h2 {
    color: #132f4c;
    letter-spacing: 0;
  }
  .ai-assistant h1 {
    margin: 0 0 5px;
    font-size: 30px;
    line-height: 1.15;
  }
  .ai-assistant h2 {
    margin: 0;
    font-size: 17px;
  }
  .ai-assistant p {
    margin: 0;
    line-height: 1.55;
  }
  .ai-assistant__intro p {
    color: #53616e;
  }
  .ai-assistant__form {
    display: grid;
    gap: 24px;
  }
  .ai-assistant__section {
    border-top: 1px solid #d7dde3;
    padding-top: 18px;
  }
  .ai-assistant__section-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    gap: 16px;
    margin-bottom: 12px;
  }
  .ai-assistant__hint {
    color: #667482;
    font-size: 13px;
  }
  .provider-groups {
    display: grid;
    gap: 14px;
  }
  .provider-group {
    display: grid;
    grid-template-columns: 106px minmax(0, 1fr);
    gap: 12px;
    align-items: start;
  }
  .provider-group__label {
    color: #496070;
    font-size: 13px;
    font-weight: 700;
    padding-top: 9px;
  }
  .provider-options,
  .task-options,
  .source-options {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .provider-option,
  .task-option {
    cursor: pointer;
  }
  .provider-option input,
  .task-option input {
    position: absolute;
    opacity: 0;
    pointer-events: none;
  }
  .provider-option span,
  .task-option span {
    display: inline-flex;
    align-items: center;
    min-height: 34px;
    border: 1px solid #b9c6d1;
    border-radius: 5px;
    background: #ffffff;
    color: #254154;
    font-size: 14px;
    font-weight: 600;
    padding: 6px 10px;
  }
  .provider-option input:checked + span,
  .task-option input:checked + span {
    border-color: #006d77;
    background: #e1f2ef;
    color: #004f57;
    box-shadow: inset 0 0 0 1px #006d77;
  }
  .provider-option input:focus-visible + span,
  .task-option input:focus-visible + span,
  .source-option input:focus-visible + span,
  .ai-assistant button:focus-visible,
  .ai-assistant textarea:focus-visible,
  .provider-link:focus-visible {
    outline: 3px solid #d58321;
    outline-offset: 2px;
  }
  .source-option {
    display: inline-flex;
    cursor: pointer;
  }
  .source-option input {
    margin: 3px 7px 0 0;
  }
  .source-option span {
    color: #2d4656;
    font-size: 14px;
  }
  .ai-assistant label[for="assistant-question"] {
    display: block;
    margin-bottom: 8px;
    color: #132f4c;
    font-size: 17px;
    font-weight: 700;
  }
  #assistant-question,
  #prompt-preview {
    display: block;
    width: 100%;
    border: 1px solid #aebcc7;
    border-radius: 5px;
    color: #17212b;
    font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    padding: 12px;
    resize: vertical;
  }
  #assistant-question {
    min-height: 112px;
    background: #ffffff;
  }
  #prompt-preview {
    min-height: 290px;
    background: #f8fafb;
  }
  .ai-assistant__question-hint {
    color: #667482;
    font-size: 13px;
    margin-top: 7px;
  }
  .ai-assistant__actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
    margin: 10px 0 12px;
  }
  .ai-assistant button,
  .provider-link {
    min-height: 36px;
    border: 1px solid #006d77;
    border-radius: 5px;
    background: #006d77;
    color: #ffffff;
    cursor: pointer;
    font: 600 14px/1.2 inherit;
    padding: 8px 12px;
    text-decoration: none;
  }
  .ai-assistant button:hover,
  .provider-link:hover {
    background: #00545c;
    color: #ffffff;
  }
  .copy-status {
    color: #435563;
    font-size: 13px;
  }
  .ai-assistant__notice {
    border-left: 4px solid #d58321;
    background: #fff8e8;
    color: #584616;
    font-size: 14px;
    line-height: 1.5;
    padding: 11px 13px;
  }
  @media (max-width: 620px) {
    .ai-assistant__intro {
      gap: 12px;
    }
    .provider-group {
      grid-template-columns: 1fr;
      gap: 6px;
    }
    .provider-group__label {
      padding-top: 0;
    }
    .ai-assistant__section-head {
      align-items: flex-start;
      flex-direction: column;
      gap: 3px;
    }
  }
</style>

<main class="ai-assistant">
  <div class="ai-assistant__intro">
    <img class="ai-assistant__mark" src="{{ '/images/touch-icon.png' | relative_url }}" alt="">
    <div>
      <h1>GPShell3 AI Assistant</h1>
      <p>Build a source-grounded question to use with your preferred AI assistant. Nothing is sent from this page.</p>
    </div>
  </div>

  <form class="ai-assistant__form" id="assistant-form">
    <section class="ai-assistant__section" aria-labelledby="provider-heading">
      <div class="ai-assistant__section-head">
        <h2 id="provider-heading">Choose an assistant</h2>
        <span class="ai-assistant__hint">The prompt is copied; no provider API is used.</span>
      </div>
      <div class="provider-groups">
        <div class="provider-group">
          <span class="provider-group__label">United States</span>
          <div class="provider-options">
            <label class="provider-option"><input type="radio" name="provider" value="chatgpt" checked><span>ChatGPT</span></label>
            <label class="provider-option"><input type="radio" name="provider" value="claude"><span>Claude</span></label>
            <label class="provider-option"><input type="radio" name="provider" value="gemini"><span>Gemini</span></label>
          </div>
        </div>
        <div class="provider-group">
          <span class="provider-group__label">Europe</span>
          <div class="provider-options">
            <label class="provider-option"><input type="radio" name="provider" value="mistral"><span>Mistral Le Chat</span></label>
            <label class="provider-option"><input type="radio" name="provider" value="euria"><span>Infomaniak Euria</span></label>
            <label class="provider-option"><input type="radio" name="provider" value="lumo"><span>Proton Lumo</span></label>
          </div>
        </div>
        <div class="provider-group">
          <span class="provider-group__label">China</span>
          <div class="provider-options">
            <label class="provider-option"><input type="radio" name="provider" value="deepseek"><span>DeepSeek</span></label>
            <label class="provider-option"><input type="radio" name="provider" value="qwen"><span>Qwen</span></label>
            <label class="provider-option"><input type="radio" name="provider" value="kimi"><span>Kimi</span></label>
            <label class="provider-option"><input type="radio" name="provider" value="glm"><span>Z.ai GLM</span></label>
          </div>
        </div>
        <div class="provider-group">
          <span class="provider-group__label">Local/private</span>
          <div class="provider-options">
            <label class="provider-option"><input type="radio" name="provider" value="local"><span>Open WebUI / Ollama</span></label>
          </div>
        </div>
      </div>
    </section>

    <section class="ai-assistant__section" aria-labelledby="task-heading">
      <div class="ai-assistant__section-head">
        <h2 id="task-heading">Choose a task</h2>
        <span class="ai-assistant__hint">All GPShell3 operations remain available in the command-help task.</span>
      </div>
      <div class="task-options">
        <label class="task-option"><input type="radio" name="task" value="gpshell3" checked><span>GPShell3 operation</span></label>
        <label class="task-option"><input type="radio" name="task" value="install"><span>Install or platform setup</span></label>
        <label class="task-option"><input type="radio" name="task" value="api"><span>C / CMake API integration</span></label>
        <label class="task-option"><input type="radio" name="task" value="pcsc"><span>PC/SC troubleshooting</span></label>
        <label class="task-option"><input type="radio" name="task" value="concepts"><span>GlobalPlatform concepts</span></label>
      </div>
    </section>

    <section class="ai-assistant__section" aria-labelledby="sources-heading">
      <div class="ai-assistant__section-head">
        <h2 id="sources-heading">Include additional sources</h2>
        <span class="ai-assistant__hint">Task-relevant project sources are selected automatically.</span>
      </div>
      <div class="source-options" id="source-options"></div>
    </section>

    <section class="ai-assistant__section">
      <label for="assistant-question">What do you need help with?</label>
      <textarea id="assistant-question" name="question" placeholder="For example: Help me diagnose why gpshell3 cannot find my PC/SC reader on Debian."></textarea>
      <p class="ai-assistant__question-hint">Do not include production keys, certificates, card dumps, or other secrets.</p>
    </section>

    <section class="ai-assistant__section" aria-labelledby="prompt-heading">
      <div class="ai-assistant__section-head">
        <h2 id="prompt-heading">Generated prompt</h2>
        <span class="ai-assistant__hint">Review it before sharing it with an external service.</span>
      </div>
      <textarea id="prompt-preview" readonly aria-label="Generated prompt"></textarea>
      <div class="ai-assistant__actions">
        <button type="button" id="copy-prompt">Copy prompt</button>
        <a class="provider-link" id="provider-link" href="https://chatgpt.com/" target="_blank" rel="noopener noreferrer">Copy prompt and open ChatGPT</a>
        <span class="copy-status" id="copy-status" role="status" aria-live="polite"></span>
      </div>
      <p class="ai-assistant__notice">Some GPShell3 actions can install or delete applets, alter keys, or change Security Domains. The generated prompt requires a safe, confirmation-first workflow, but you remain responsible for the target card and commands you run.</p>
    </section>
  </form>
</main>

<script>
  (function () {
    'use strict';

    var providers = {
      chatgpt: { name: 'ChatGPT', url: 'https://chatgpt.com/' },
      claude: { name: 'Claude', url: 'https://claude.ai/new' },
      gemini: { name: 'Gemini', url: 'https://gemini.google.com/app' },
      mistral: { name: 'Mistral Le Chat', url: 'https://chat.mistral.ai/' },
      euria: { name: 'Infomaniak Euria', url: 'https://euria.infomaniak.com/' },
      lumo: { name: 'Proton Lumo', url: 'https://lumo.proton.me/' },
      deepseek: { name: 'DeepSeek', url: 'https://chat.deepseek.com/' },
      qwen: { name: 'Qwen', url: 'https://chat.qwen.ai/' },
      kimi: { name: 'Kimi', url: 'https://www.kimi.com/' },
      glm: { name: 'Z.ai GLM', url: 'https://chat.z.ai/' },
      local: { name: 'a local Open WebUI or Ollama setup', url: 'https://openwebui.com/' }
    };

    var sources = {
      manual: {
        label: 'GPShell3 manual',
        url: 'https://github.com/kaoh/globalplatform/blob/master/gpshell/src/gpshell3.1.md',
        note: 'Commands, syntax, options, supported workflows, and defaults.'
      },
      examples: {
        label: 'GPShell3 examples',
        url: 'https://github.com/kaoh/globalplatform/blob/master/gpshell/examples/gpshell3/README.md',
        note: 'Real-card example prerequisites and operation safety notes.'
      },
      readme: {
        label: 'Project README',
        url: 'https://github.com/kaoh/globalplatform/blob/master/README.md',
        note: 'Release packages, source builds, Homebrew, vcpkg, and SDK overview.'
      },
      site: {
        label: 'GlobalPlatform project site',
        url: 'https://kaoh.github.io/globalplatform/',
        note: 'Published project overview, downloads, and documentation links.'
      },
      api: {
        label: 'C API documentation',
        url: 'https://kaoh.github.io/globalplatform/api/index.html',
        note: 'Published C API reference.'
      },
      vcpkg: {
        label: 'GlobalPlatform vcpkg registry',
        url: 'https://github.com/kaoh/globalplatform-vcpkg-registry',
        note: 'C and CMake package integration.'
      },
      homebrew: {
        label: 'GlobalPlatform Homebrew tap',
        url: 'https://github.com/kaoh/homebrew-globalplatform',
        note: 'Homebrew installation for Linux and macOS.'
      },
      pcsc: {
        label: 'PC/SC connection plugin documentation',
        url: 'https://kaoh.github.io/globalplatform/connectionPlugins.html',
        note: 'Connection plugin purpose and implementation guidance.'
      },
      overview: {
        label: 'Repository GlobalPlatform overview',
        url: 'https://kaoh.github.io/globalplatform/globalPlatformSpecification.html',
        note: 'Project educational overview; not a normative specification.'
      },
      specification: {
        label: 'Official GlobalPlatform specifications',
        url: 'https://globalplatform.org/specs-library/',
        note: 'Normative source for GlobalPlatform requirements.'
      }
    };

    var taskSources = {
      gpshell3: ['manual', 'examples', 'readme', 'site', 'pcsc', 'specification'],
      install: ['readme', 'site', 'vcpkg', 'homebrew', 'pcsc', 'manual'],
      api: ['api', 'readme', 'vcpkg', 'pcsc', 'specification'],
      pcsc: ['manual', 'examples', 'readme', 'pcsc', 'site'],
      concepts: ['manual', 'overview', 'specification', 'site']
    };

    var taskInstructions = {
      gpshell3: 'Focus on the documented GPShell3 command line. Cover any supported GPShell3 workflow that is relevant, including secure channels, CAP lifecycle, DAP, delegated management, keys, Security Domains, personalization, raw APDUs, and PC/SC readers.',
      install: 'Focus on the target operating system, supported installation channel, dependencies, PC/SC service/reader setup, and verification steps.',
      api: 'Focus on supported C APIs and CMake package integration. Provide a small complete code example only after identifying the needed API and platform assumptions.',
      pcsc: 'Focus on diagnosis of reader discovery, the operating-system PC/SC service/library, the GlobalPlatform connection plugin, and the distinction between them.',
      concepts: 'Explain concepts accurately and distinguish the project overview from requirements defined by official GlobalPlatform specifications.'
    };

    var form = document.getElementById('assistant-form');
    var sourceOptions = document.getElementById('source-options');
    var question = document.getElementById('assistant-question');
    var preview = document.getElementById('prompt-preview');
    var providerLink = document.getElementById('provider-link');
    var copyButton = document.getElementById('copy-prompt');
    var copyStatus = document.getElementById('copy-status');

    Object.keys(sources).forEach(function (key) {
      var label = document.createElement('label');
      var input = document.createElement('input');
      var text = document.createElement('span');
      label.className = 'source-option';
      input.type = 'checkbox';
      input.name = 'source';
      input.value = key;
      text.textContent = sources[key].label;
      label.appendChild(input);
      label.appendChild(text);
      sourceOptions.appendChild(label);
    });

    function selectedValue(name) {
      return form.querySelector('input[name="' + name + '"]:checked').value;
    }

    function updateSourceDefaults() {
      var task = selectedValue('task');
      var defaults = taskSources[task];
      form.querySelectorAll('input[name="source"]').forEach(function (input) {
        input.checked = defaults.indexOf(input.value) !== -1;
      });
    }

    function selectedSources() {
      return Array.prototype.map.call(
        form.querySelectorAll('input[name="source"]:checked'),
        function (input) { return sources[input.value]; }
      );
    }

    function buildPrompt() {
      var provider = providers[selectedValue('provider')];
      var task = selectedValue('task');
      var request = question.value.trim() || '[Describe your goal, platform, reader/card environment, and any non-secret error output.]';
      var references = selectedSources();
      var referenceText = references.map(function (source) {
        return '- ' + source.label + ': ' + source.url + '\n  Use for: ' + source.note;
      }).join('\n');

      return [
        'You are helping a user work with the GlobalPlatform project and GPShell3. This prompt is being used with ' + provider.name + '.',
        '',
        'User request:',
        request,
        '',
        'Task framing:',
        taskInstructions[task],
        '',
        'Authoritative and supporting sources:',
        referenceText,
        '',
        'Response requirements:',
        '- Base factual claims on the sources above. Cite each relevant source by title and URL; say clearly when a source cannot be accessed or does not establish a point.',
        '- Treat the official GlobalPlatform specification as normative. Treat project documentation and examples as implementation guidance, not a replacement for the specification.',
        '- Do not invent command options, APIs, card capabilities, AIDs, SCP implementations, status-word meanings, or installation instructions. State assumptions and ask concise follow-up questions when facts are missing.',
        '- Match commands and code to the user\'s platform. Prefer read-only diagnostics and documented commands before proposing changes.',
        '- Never request, generate, expose, or repeat production keys, certificates, card dumps, or other secrets. Use placeholders for sensitive values.',
        '- For any operation that may authenticate to a card, install/delete an applet, change keys, alter a Security Domain, personalize a card, or send a state-changing APDU: first explain the impact and provide read-only checks where possible. Before providing final executable commands, request explicit confirmation that the user controls a non-production target and has verified the reader, card, protocol, expected AIDs, and rollback/recovery plan.',
        '- Separate safe exploratory steps from state-changing steps. Do not imply that commands are safe for an unknown or production card.'
      ].join('\n');
    }

    function updatePrompt() {
      var provider = providers[selectedValue('provider')];
      preview.value = buildPrompt();
      providerLink.href = provider.url;
      providerLink.textContent = selectedValue('provider') === 'local' ? 'Copy prompt and open local setup guide' : 'Copy prompt and open ' + provider.name;
      copyStatus.textContent = '';
    }

    form.addEventListener('change', function (event) {
      if (event.target.name === 'task') {
        updateSourceDefaults();
      }
      updatePrompt();
    });
    question.addEventListener('input', updatePrompt);
    function copyWithFallback() {
      var copied = false;
      try {
        copied = document.execCommand('copy');
      } catch (error) {
        copied = false;
      }
      copyStatus.textContent = copied ? 'Prompt copied.' : 'Copy failed. Select the prompt and copy it manually.';
    }
    function copyPrompt() {
      preview.select();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(preview.value).then(function () {
          copyStatus.textContent = 'Prompt copied.';
        }).catch(copyWithFallback);
      } else {
        copyWithFallback();
      }
    }
    copyButton.addEventListener('click', function () {
      copyPrompt();
    });
    providerLink.addEventListener('click', function () {
      copyPrompt();
    });

    updateSourceDefaults();
    updatePrompt();
  }());
</script>
