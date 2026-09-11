package com.xlink.android.vpn

import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.N)
class VpnTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTileState()
    }

    override fun onClick() {
        super.onClick()
        val isRunning = VpnStateHolder.isAnyRunning()
        val intent = Intent(this, XlinkVpnService::class.java).apply {
            action = if (isRunning) XlinkVpnService.ACTION_STOP_ALL else XlinkVpnService.ACTION_START_ALL
        }
        if (!isRunning) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        } else {
            startService(intent)
        }
        updateTileState()
    }

    private fun updateTileState() {
        val tile = qsTile ?: return
        val isRunning = VpnStateHolder.isAnyRunning()
        tile.state = if (isRunning) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = if (isRunning) "Xlink: 运行中" else "Xlink: 已停止"
        tile.updateTile()
    }
}