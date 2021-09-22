import { jobs, SchedulerJob } from './index';
import { configuredJobs } from './configured-jobs';
import { log } from '../../lib/logger';
import { getConfiguration } from '../../lib/get-configuration';
import cron from 'node-cron';
import { 
  WAZUH_STATISTICS_DEFAULT_STATUS, 
  WAZUH_STATISTICS_DEFAULT_PREFIX, 
  WAZUH_STATISTICS_DEFAULT_NAME, 
  WAZUH_STATISTICS_TEMPLATE_NAME,
} from '../../../common/constants';
import { statisticsTemplate } from '../../integration-files/statistics-template';

const blueWazuh = '\u001b[34mwazuh\u001b[39m';
const schedulerErrorLogColors = [blueWazuh, 'scheduler', 'error'];
const schedulerJobs = [];

let STATISTICS_ENABLED, STATISTICS_INDEX_PATTERN, STATISTICS_INDEX_PREFIX;

/**
 * Set the statistics variables
 * @param context
 */
 function initStatisticsConfiguration(context){
  try{
    const appConfig = getConfiguration();
    const prefixTemplateName = appConfig['cron.prefix'] || WAZUH_STATISTICS_DEFAULT_PREFIX;
    const statisticsIndicesTemplateName = appConfig['cron.statistics.index.name'] || WAZUH_STATISTICS_DEFAULT_NAME;
    STATISTICS_ENABLED = appConfig && typeof appConfig['cron.statistics.status'] !== 'undefined'
      ? appConfig['cron.statistics.status'] &&
        appConfig['cron.statistics.status'] !== 'worker'
      : WAZUH_STATISTICS_DEFAULT_STATUS;

    STATISTICS_INDEX_PATTERN = `${prefixTemplateName}-${statisticsIndicesTemplateName}-*`;
    const lastCharIndexPattern = STATISTICS_INDEX_PATTERN[STATISTICS_INDEX_PATTERN.length - 1];
    if (lastCharIndexPattern !== '*') {
      STATISTICS_INDEX_PATTERN += '*';
    };
    STATISTICS_INDEX_PREFIX = STATISTICS_INDEX_PATTERN.slice(0,STATISTICS_INDEX_PATTERN.length - 1);

    log(
      'statistics:initStatisticsConfiguration',
      `cron.statistics.status: ${STATISTICS_ENABLED}`,
      'debug'
    );

    log(
      'statistics:initStatisticsConfiguration',
      `wazuh.statistics.pattern: ${STATISTICS_INDEX_PATTERN} (index prefix: ${STATISTICS_INDEX_PREFIX})`,
      'debug'
    );
  }catch(error){
    const errorMessage = error.message || error;
    log(
      'statistics:initStatisticsConfiguration',
      errorMessage
    );
    context.wazuh.logger.error(errorMessage)
  }
};
/**
* Wait until Kibana server is ready
*/
const checkKibanaStatus = async function (context) {
  try {
     log(
       'scheduler-handler:checkKibanaStatus',
       'Waiting for Kibana and Elasticsearch servers to be ready...',
       'debug'
     );
 
    await checkElasticsearchServer(context);
    await checkTemplate(context);
    return;
  } catch (error) {
     log(
       'scheduler-handler:checkKibanaStatus',
       error.mesage ||error
     );
     try{
       await delay(3000);
       await checkKibanaStatus(context);
     }catch(error){};
  }
 }
 
 
 /**
  * Check Elasticsearch Server status and Kibana index presence
  */
 const checkElasticsearchServer = async function (context) {
   try {
     const data = await context.core.elasticsearch.client.asInternalUser.indices.exists({
       index: context.server.config.kibana.index
     });
 
     return data.body;
   } catch (error) {
     log('scheduler-handler:checkElasticsearchServer', error.message || error);
     return Promise.reject(error);
   }
 }


 /**
 * Verify wazuh-statistics template
 */
const checkTemplate = async function (context) {
  try {
    log(
      'scheduler-handler:checkTemplate',
      'Updating the statistics template',
      'debug'
    );


    try {
      // Check if the template already exists
      const currentTemplate = await context.core.elasticsearch.client.asInternalUser.indices.getTemplate({
        name: WAZUH_STATISTICS_TEMPLATE_NAME
      });
      // Copy already created index patterns
      statisticsTemplate.index_patterns = currentTemplate.body[WAZUH_STATISTICS_TEMPLATE_NAME].index_patterns;
    }catch (error) {
      // Init with the default index pattern
      statisticsTemplate.index_patterns = [STATISTICS_INDEX_PATTERN];
    }

    // Check if the user is using a custom pattern and add it to the template if it does
    if (!statisticsTemplate.index_patterns.includes(STATISTICS_INDEX_PATTERN)) {
      statisticsTemplate.index_patterns.push(STATISTICS_INDEX_PATTERN);
    };

    // Update the statistics template
    await context.core.elasticsearch.client.asInternalUser.indices.putTemplate({
      name: WAZUH_STATISTICS_TEMPLATE_NAME,
      body: statisticsTemplate
    });
    log(
      'scheduler-handler:checkTemplate',
      'Updated the statistics template',
      'debug'
    );
  } catch (error) {
    const errorMessage = `Something went wrong updating the statistics template ${error.message || error}`;
    log(
      'scheduler-handler:checkTemplate',
      errorMessage
    );
    context.wazuh.logger.error(schedulerErrorLogColors, errorMessage);
    throw error;
  }
}

export async function jobSchedulerRun(context){
  // Check Kibana index and if it is prepared, start the initialization of Wazuh App.
  initStatisticsConfiguration(context);
  if(!STATISTICS_ENABLED) {
    log(
      'scheduler-handler:jobSchedulerRun',
      'Statistics configuration status is false. Skipping job',
      'debug'
    );
    context.wazuh.logger.info('Statistics configuration status is false. Skipping job');
    return;
  }

  await checkKibanaStatus(context);
  for (const job in configuredJobs({})) {
    const schedulerJob: SchedulerJob = new SchedulerJob(job, context);
    schedulerJobs.push(schedulerJob);
    const task = cron.schedule(
      jobs[job].interval,
      () => schedulerJob.run(),
    );
  }
}