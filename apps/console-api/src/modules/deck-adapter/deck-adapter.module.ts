import {Module} from '@nestjs/common';
import {ConfigStorageModule} from '../config-storage/config-storage.module';
import {DeckAdapterController,DeckSessionsController} from './deck-adapter.controller';
import {DeckAdapterService} from './deck-adapter.service';
import {DeckSessionService} from './deck-session.service';
import {DeckSessionGuard} from './deck-session.guard';
@Module({imports:[ConfigStorageModule],controllers:[DeckAdapterController,DeckSessionsController],providers:[DeckAdapterService,DeckSessionService,DeckSessionGuard],exports:[DeckSessionService]})
export class DeckAdapterModule{}
