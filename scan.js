#!/usr/bin/env node
"use strict";

const fs = require('fs');
const { promisify } = require('util');
const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);
const CloudConformity = require("cloud-conformity");
const readDir = promisify(fs.readdir);
const readOptions = { encoding: "utf8" }

const RESULTS_FILE_PATH='results.json'

const computeFailures = async (result, messages) => {
  const resultAsString = JSON.stringify(result, null, 2)
  console.log(resultAsString);
  await writeFile(RESULTS_FILE_PATH, resultAsString);
  return result.failure.reduce((total, result) => {
    messages.push(`Risk: ${result['riskLevel']} \tReason: ${result.description}`);
    if (result['riskLevel'] === 'EXTREME'){
      total.extreme +=1;
    } else if (result['riskLevel'] === 'VERY_HIGH') {
      total.veryHigh +=1;
    } else if (result['riskLevel'] === 'HIGH') {
      total.high +=1;
    } else if (result['riskLevel'] === 'MEDIUM') {
      total.medium +=1;
    } else if (result['riskLevel'] === 'LOW') {
      total.low +=1;
    }
    return total;
  }, {
    extreme: 0,
    veryHigh: 0,
    high: 0,
    medium: 0,
    low: 0,
  });
}

const scan = async (templatePath, ccApiKey, accountId, templatesDirPath) => {
  const cc = new CloudConformity.CloudConformity(ccApiKey);
  if (templatesDirPath) {
    return batchScanTemplates(cc, templatesDirPath, accountId)
  }
  return scanTemplate(cc, templatePath, accountId)
}

const failOnFailure = (failures, acceptedQty) => {
  return ((failures.extreme > acceptedQty.extreme) || (failures.veryHigh > acceptedQty.veryHigh) || (failures.high > acceptedQty.high) || (failures.medium > acceptedQty.medium) || (failures.low > acceptedQty.low))
};

const batchScanTemplates = async (cc, templatesDirPath, accountId) => {
  const dir = await readDir(templatesDirPath, readOptions)
  return Promise.all(dir.map(async (template) => {
      const fullPath = templatesDirPath + "/" + template
      return scanTemplate(cc, fullPath, accountId)
  }))
}

const scanTemplate = async (cc, templatePath, accountId) => {
  const template = await readFile(templatePath, readOptions);
  // Scans the template using Conformity module.
  console.log("Scan template: (%s)", templatePath)
  const result = await cc.scanACloudFormationTemplateAndReturAsArrays(template, accountId);
  const messages = [];
  const results = await computeFailures(result, messages);
  return {
      template: templatePath,
      detections: result.failure,
      results: results,
      messages: messages
  };
}

const apikey = process.env.v1_apikey;
const templatePath = process.env.templatePath;
const acceptedResults = {
  extreme: process.env.maxExtreme? process.env.maxExtreme : Number.MAX_SAFE_INTEGER,
  veryHigh: process.env.maxVeryHigh? process.env.maxVeryHigh : Number.MAX_SAFE_INTEGER,
  high: process.env.maxHigh? process.env.maxHigh : Number.MAX_SAFE_INTEGER,
  medium: process.env.maxMedium? process.env.maxMedium: Number.MAX_SAFE_INTEGER,
  low: process.env.maxLow? process.env.maxLow : Number.MAX_SAFE_INTEGER
};
const outputResults = process.env.cc_output_results? true : false;
const accountId = process.env.accountId;
const templatesDirPath = process.env.templatesDirPath;

scan(templatePath, apikey, accountId, templatesDirPath)
  .then(value => {
    const results = Array.isArray(value) ? value : [value]
    const COMPLIANT_MESSAGE = "Template passes configured checks."
    const NON_COMPLIANT_MESSAGE = "Security and/or misconfiguration issue(s) found in template(s): "
    const nonCompliantTemplates = [];
    let isCompliant = true;
    for (const result of results) {
        console.log(`\nFailures found: ${JSON.stringify(result.results, null, 2)}`);
        console.log('\n');
        console.log(`Quantity of failures allowed: ${JSON.stringify(acceptedResults, null, 2)}`);
        if (outputResults && result.messages) {
            console.log('\n');
            console.log('Results:\n');
            console.log(result.messages.join('\n'));
        }
        console.log('\n');
        if (failOnFailure(result.results, acceptedResults)) {
            isCompliant = false;
            nonCompliantTemplates.push(result.template)
        }
    }
    return {
        status: isCompliant,
        message: isCompliant ? COMPLIANT_MESSAGE : NON_COMPLIANT_MESSAGE + " [" + nonCompliantTemplates + "]"
    };
  })
  .then(res => {
    console.log(res.message)
    if (!res.status) {
        process.exit(1);
    }
    process.exit(0);
  })
  .catch(err => {
    console.error(err);
  });
