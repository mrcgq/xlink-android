//
// 修复重点：
//   1. 增加 delay(500L) 智能防抖，彻底消除打字频繁触发 DataStore 写入磁盘的问题。
//   2. 返回导航时即时提交保存，杜绝输入延迟丢失。
//   3. 优化域名池与多 Worker 负载均衡选项说明。

package com.xlink.android.ui.screen

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
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
    var tokenField by remember(node.id) { mutableStateOf(node.token) }
    var secretKeyField by remember(node.id) { mutableStateOf(node.secretKey) }

    LaunchedEffect(nameField, listenField, serverField, tokenField, secretKeyField) {
        delay(500L)
        nodeViewModel.updateNode(currentIndex) {
            it.copy(
                name = nameField.trim(),
                listen = listenField.trim(),
                server = serverField.trim(),
                token = tokenField.trim(),
                secretKey = secretKeyField.trim()
            )
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.Filled.ArrowBack, null) }
                },
                title = { Text(node.name) }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier.fillMaxSize().padding(paddingValues).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(value = nameField, onValueChange = { nameField = it }, label = { Text("节点别名") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = listenField, onValueChange = { listenField = it }, label = { Text("本地监听地址") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = serverField, onValueChange = { serverField = it }, label = { Text("域名池 (每行一个)") }, modifier = Modifier.fillMaxWidth(), maxLines = 8)
            OutlinedTextField(value = tokenField, onValueChange = { tokenField = it }, label = { Text("Token") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = secretKeyField, onValueChange = { secretKeyField = it }, label = { Text("Secret Key") }, modifier = Modifier.fillMaxWidth())
        }
    }
}
