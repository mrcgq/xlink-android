package com.xlink.android.ui.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.xlink.android.data.model.NodeConfig
import com.xlink.android.viewmodel.NodeViewModel
import kotlinx.coroutines.delay

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeEditScreen(nodeViewModel: NodeViewModel, onBack: () -> Unit) {
    val currentIndex by nodeViewModel.currentIndex.collectAsStateWithLifecycle()
    val nodes by nodeViewModel.nodes.collectAsStateWithLifecycle()
    val node = nodes.getOrNull(currentIndex)

    if (node == null) {
        LaunchedEffect(Unit) { onBack() }
        return
    }

    var nameField by remember(node.id) { mutableStateOf(node.name) }
    var listenField by remember(node.id) { mutableStateOf(node.listen) }
    var serverField by remember(node.id) { mutableStateOf(node.server) }
    var ipField by remember(node.id) { mutableStateOf(node.ip) }
    var tokenField by remember(node.id) { mutableStateOf(node.token) }
    var secretKeyField by remember(node.id) { mutableStateOf(node.secretKey) }
    var fallbackIpField by remember(node.id) { mutableStateOf(node.fallbackIp) }
    var routingModeField by remember(node.id) { mutableIntStateOf(node.routingMode) }
    var strategyModeField by remember(node.id) { mutableIntStateOf(node.strategyMode) }
    var rulesField by remember(node.id) { mutableStateOf(node.rules) }

    LaunchedEffect(
        nameField, listenField, serverField, ipField, tokenField,
        secretKeyField, fallbackIpField, routingModeField, strategyModeField, rulesField
    ) {
        delay(400L)
        nodeViewModel.updateNode(currentIndex) {
            it.copy(
                name = nameField.trim(),
                listen = listenField.trim(),
                server = serverField.trim(),
                ip = ipField.trim(),
                token = tokenField.trim(),
                secretKey = secretKeyField.trim(),
                fallbackIp = fallbackIpField.trim(),
                routingMode = routingModeField,
                strategyMode = strategyModeField,
                rules = rulesField.trim()
            )
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.Filled.ArrowBack, contentDescription = "返回") }
                },
                title = { Text(node.name.ifBlank { "配置节点" }, fontWeight = FontWeight.Bold) }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            OutlinedTextField(value = nameField, onValueChange = { nameField = it }, label = { Text("节点别名") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = listenField, onValueChange = { listenField = it }, label = { Text("本地监听地址") }, placeholder = { Text("127.0.0.1:10808") }, modifier = Modifier.fillMaxWidth())

            OutlinedTextField(
                value = serverField,
                onValueChange = { serverField = it },
                label = { Text("域名池 (每行一个，支持 SNI#IP:Port)") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 3,
                maxLines = 6,
                placeholder = { Text("cdn.worker.dev:443\n或: my.sni.com#104.16.1.1:443") }
            )

            OutlinedTextField(value = ipField, onValueChange = { ipField = it }, label = { Text("指定 IP (Cloudflare 优选 IP / 反代域名)") }, placeholder = { Text("如: 172.64.229.28 或 cf.877774.xyz") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = tokenField, onValueChange = { tokenField = it }, label = { Text("Token (协议认证)") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = secretKeyField, onValueChange = { secretKeyField = it }, label = { Text("Secret Key (Worker 鉴权密钥)") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = fallbackIpField, onValueChange = { fallbackIpField = it }, label = { Text("回源 IP (Fallback IP)") }, placeholder = { Text("如: 43.162.119.244 (选填)") }, modifier = Modifier.fillMaxWidth())

            Text("路由模式", fontSize = 13.sp, fontWeight = FontWeight.Medium)
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                FilterChip(selected = routingModeField == NodeConfig.ROUTING_GLOBAL, onClick = { routingModeField = NodeConfig.ROUTING_GLOBAL }, label = { Text("全局代理") })
                FilterChip(selected = routingModeField == NodeConfig.ROUTING_SMART, onClick = { routingModeField = NodeConfig.ROUTING_SMART }, label = { Text("智能分流") })
            }

            Text("负载策略", fontSize = 13.sp, fontWeight = FontWeight.Medium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(selected = strategyModeField == NodeConfig.STRATEGY_RANDOM, onClick = { strategyModeField = NodeConfig.STRATEGY_RANDOM }, label = { Text("[Random] 混沌") })
                FilterChip(selected = strategyModeField == NodeConfig.STRATEGY_RR, onClick = { strategyModeField = NodeConfig.STRATEGY_RR }, label = { Text("[RR] 轮询") })
                FilterChip(selected = strategyModeField == NodeConfig.STRATEGY_HASH, onClick = { strategyModeField = NodeConfig.STRATEGY_HASH }, label = { Text("[Hash] 狙击") })
            }

            OutlinedTextField(
                value = rulesField,
                onValueChange = { rulesField = it },
                label = { Text("分流规则 (格式: 关键词,节点域名)") },
                placeholder = { Text("# 示例:\n# youtube.com,cdn.worker.dev:443") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 3,
                maxLines = 6
            )
        }
    }
}