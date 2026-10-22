"use strict";

const catalog = JSON.parse(document.getElementById("rule-data").textContent);
const form = document.getElementById("rule-filters");
const query = document.getElementById("rule-query");
const severity = document.getElementById("severity-filter");
const confidence = document.getElementById("confidence-filter");
const policy = document.getElementById("policy-filter");
const count = document.getElementById("result-count");
const list = document.getElementById("rule-list");

function element(name, className, value) {
  const node = document.createElement(name);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = value;
  return node;
}

function pill(value, className) {
  return element("span", `pill ${className || ""}`.trim(), value);
}

function ruleCard(rule) {
  const item = element("li", "rule-card");
  const heading = element("div", "rule-title");
  const link = element("a", "", rule.id);
  link.href = `https://github.com/DicksonWu654/nightshade/blob/v0.1.0/docs/detectors/${encodeURIComponent(rule.id)}.md`;
  link.setAttribute("aria-label", `${rule.id} documentation on GitHub`);
  heading.append(link);
  item.append(heading, element("p", "", rule.description));
  const meta = element("div", "rule-meta");
  meta.append(
    pill(`Severity: ${rule.severity}`, `severity-${rule.severity}`),
    pill(`Confidence: ${rule.confidence}`),
    pill(rule.maturity)
  );
  if (rule.policyRequired) meta.append(pill("Policy required"));
  item.append(meta);
  return item;
}

function render() {
  const term = query.value.trim().toLowerCase();
  const matches = catalog.filter((rule) => {
    const searchable = [rule.id, rule.description, ...(rule.requires || [])].join(" ").toLowerCase();
    return (!term || searchable.includes(term)) &&
      (!severity.value || rule.severity === severity.value || (rule.severityLevels || []).includes(severity.value)) &&
      (!confidence.value || rule.confidence === confidence.value) &&
      (!policy.value || (policy.value === "required" ? rule.policyRequired : !rule.policyRequired));
  });
  count.textContent = `${matches.length} of ${catalog.length} rules shown`;
  if (matches.length === 0) {
    list.replaceChildren(element("li", "empty-state", "No rules match these filters."));
  } else {
    list.replaceChildren(...matches.map(ruleCard));
  }
}

form.addEventListener("input", render);
form.addEventListener("change", render);
form.addEventListener("submit", (event) => event.preventDefault());
document.getElementById("clear-filters").addEventListener("click", () => {
  form.reset();
  render();
  query.focus();
});
const initialQuery = new URLSearchParams(location.search).get("q");
if (initialQuery) query.value = initialQuery;
render();
