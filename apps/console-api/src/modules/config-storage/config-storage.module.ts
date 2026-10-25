import { Module } from '@nestjs/common';
import { CONFIGURATION_CAPTURE_REPOSITORY } from '../configuration/configuration.types';
import { ConfigurationRepositoryService } from './configuration-repository.service';
import { SnapshotCryptoService } from './snapshot-crypto.service';
import { CONFIGURATION_DECK_REPOSITORY } from '../deck-adapter/deck.types';

@Module({providers:[SnapshotCryptoService,ConfigurationRepositoryService,
  {provide:CONFIGURATION_CAPTURE_REPOSITORY,useExisting:ConfigurationRepositoryService},
  {provide:CONFIGURATION_DECK_REPOSITORY,useExisting:ConfigurationRepositoryService}],
  exports:[SnapshotCryptoService,ConfigurationRepositoryService,CONFIGURATION_CAPTURE_REPOSITORY,CONFIGURATION_DECK_REPOSITORY]})
export class ConfigStorageModule {}
