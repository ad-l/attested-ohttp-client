#!/usr/bin/env node
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
import { OhttpClientBuilder } from '../src/ohttp-client';
import { Client } from '../src/ohttp';
import { readFileSync } from 'fs';

async function main() {
  const argv = await yargs(hideBin(process.argv))
    .option('url', {
      alias: 'u',
      type: 'string',
      description: 'Target URL for the OHTTP request',
      demandOption: true
    })
    .option('method', {
      alias: 'm',
      type: 'string',
      choices: ['GET', 'POST'],
      default: 'POST'
    })
    .option('data', {
      alias: 'd',
      type: 'string',
      description: 'Request body data'
    })
    .option('config', {
      alias: 'c',
      type: 'string',
      description: 'Path to key configuration file',
      default: 'certs/kms-cert.pem'
    })
    .parse();

  try {
    const config = readFileSync(argv.config, 'utf-8');
    const client = await new OhttpClientBuilder()
      .withConfigHex(config)
      .build();
    
    const request = new Request(argv.url, {
      method: argv.method,
      body: argv.data ? argv.data : undefined
    });
    
    const context = await client.encapsulateRequest(request);
    const response = await context.decapsulateResponse(await fetch(context.request.request(argv.url)));
    
    console.log(`Response Status: ${response.status}`);
    console.log('Headers:', Object.fromEntries(response.headers));
    console.log('Body:', await response.text());
  } catch (err) {
    console.error('Error:', err instanceof Error ? err.message : err);
    process.exit(1);
  }
}

main();
